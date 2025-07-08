const ipRequestMap = new Map();
const RATE_LIMIT_WINDOW = 60000; // 1 minute in milliseconds
const MAX_REQUESTS_PER_WINDOW = 10; // Allow 10 requests per minute per user
const IP_CLEANUP_INTERVAL = 300000; // 5 minutes

// Function to get the real client IP address
const getClientIp = (req) => {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
        // 'x-forwarded-for' can be a comma-separated list of IPs. The first one is the original client.
        const ip = forwarded.split(',')[0].trim();
        return ip;
    }
    return req.socket?.remoteAddress || req.headers['x-real-ip'] || '127.0.0.1';
};

// Periodically clean up old entries from the map
setInterval(() => {
    const now = Date.now();
    for (const [ip, timestamps] of ipRequestMap.entries()) {
        const recentTimestamps = timestamps.filter(ts => now - ts < RATE_LIMIT_WINDOW);
        if (recentTimestamps.length === 0) {
            ipRequestMap.delete(ip);
        } else {
            ipRequestMap.set(ip, recentTimestamps);
        }
    }
}, IP_CLEANUP_INTERVAL);

export default async function handler(request, response) {
    const ip = getClientIp(request);
    const now = Date.now();

    if (!ipRequestMap.has(ip)) {
        ipRequestMap.set(ip, []);
    }

    const requests = ipRequestMap.get(ip);
    
    const recentRequests = requests.filter(timestamp => now - timestamp < RATE_LIMIT_WINDOW);
    ipRequestMap.set(ip, recentRequests);

    if (recentRequests.length >= MAX_REQUESTS_PER_WINDOW) {
        return response.status(429).json({ error: 'Rate limit exceeded. Please try again in a minute.' });
    }
    
    recentRequests.push(now);

    const domain = request.query.domain;
    const vtApiKey = process.env.VT_API_KEY;

    if (!domain) {
        return response.status(400).json({ error: 'Domain is required' });
    }

    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/;
    if (!domainRegex.test(domain)) {
        return response.status(400).json({ error: 'Invalid domain format' });
    }

    try {
        const crtShRes = await fetch(`https://crt.sh/?q=%.${domain}&output=json`);
        if (!crtShRes.ok) throw new Error('crt.sh API request failed.');
        const crtShData = await crtShRes.json();
        const subdomains = [...new Set(crtShData.map(item => item.name_value.replace(/\*\./g, '').toLowerCase()))].sort();

        const enrichedData = await Promise.all(subdomains.map(async (subdomain) => {
            let vtResults = null;
            let screenshotUrl = null;
            let openPorts = [];

            if (vtApiKey) {
                try {
                    const vtRes = await fetch(`https://www.virustotal.com/api/v3/domains/${subdomain}`, { headers: { 'x-apikey': vtApiKey } });
                    if (vtRes.ok) {
                        const vtData = await vtRes.json();
                        vtResults = vtData?.data?.attributes?.last_analysis_stats;
                    }
                } catch (e) { /* Ignore VT errors */ }
            }

            try {
                const url = `https://${subdomain}`;
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 3000);
                const portRes = await fetch(url, { signal: controller.signal });
                clearTimeout(timeoutId);

                if (portRes.ok) {
                    openPorts.push(443);
                    screenshotUrl = `https://s.wordpress.com/mshots/v1/${encodeURIComponent(url)}?w=400`;
                }
            } catch (e) { /* Ignore connection errors */ }

            return { subdomain, vtResults, screenshotUrl, openPorts };
        }));

        response.status(200).json({ nodes: enrichedData });

    } catch (error) {
        response.status(500).json({ error: error.message });
    }
}
