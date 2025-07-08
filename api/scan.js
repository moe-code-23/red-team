import { getClientIp } from '@/utils/get-client-ip';

const ipRequestMap = new Map();
const RATE_LIMIT_WINDOW = 60000; // 1 minute in milliseconds
const MAX_REQUESTS_PER_WINDOW = 10; // Allow 10 requests per minute per user
const IP_CLEANUP_INTERVAL = 300000; // 5 minutes

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
    
    // Filter out requests that are outside the time window
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

    // Basic domain validation regex
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/;
    if (!domainRegex.test(domain)) {
        return response.status(400).json({ error: 'Invalid domain format' });
    }

    try {
        // 1. Get subdomains from crt.sh
        const crtShRes = await fetch(`https://crt.sh/?q=%.${domain}&output=json`);
        if (!crtShRes.ok) throw new Error('crt.sh API request failed.');
        const crtShData = await crtShRes.json();
        const subdomains = [...new Set(crtShData.map(item => item.name_value.replace(/\*\./g, '').toLowerCase()))].sort();

        // 2. Enrich each subdomain
        const enrichedData = await Promise.all(subdomains.map(async (subdomain) => {
            let vtResults = null;
            let screenshotUrl = null;
            let openPorts = [];

            // a. VirusTotal Scan
            if (vtApiKey) {
                try {
                    const vtRes = await fetch(`https://www.virustotal.com/api/v3/domains/${subdomain}`, { headers: { 'x-apikey': vtApiKey } });
                    if (vtRes.ok) {
                        const vtData = await vtRes.json();
                        vtResults = vtData.data.attributes.last_analysis_stats;
                    }
                } catch (e) { /* Ignore VT errors */ }
            }

            // b. Check common web ports and get screenshot
            for (const port of [80, 443]) {
                try {
                    const protocol = port === 443 ? 'https' : 'http';
                    const url = `${protocol}://${subdomain}`;
                    const controller = new AbortController();
                    const timeoutId = setTimeout(() => controller.abort(), 3000); // 3-second timeout
                    const portRes = await fetch(url, { signal: controller.signal });
                    clearTimeout(timeoutId);

                    if (portRes.ok) {
                        openPorts.push(port);
                        // Use a screenshot API if available (e.g., screenshotapi.net)
                        // For this example, we'll just use a placeholder
                        screenshotUrl = `https://s.wordpress.com/mshots/v1/${encodeURIComponent(url)}?w=400`;
                    }
                } catch (e) { /* Ignore connection errors */ }
            }

            return { subdomain, vtResults, screenshotUrl, openPorts };
        }));

        response.status(200).json({ nodes: enrichedData });

    } catch (error) {
        response.status(500).json({ error: error.message });
    }
}
