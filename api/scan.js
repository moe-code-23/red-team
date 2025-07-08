const ipRequestMap = new Map();
const RATE_LIMIT_WINDOW = 60000; // 1 minute in milliseconds
const MAX_REQUESTS_PER_WINDOW = 10; // Allow 10 requests per minute per user
const IP_CLEANUP_INTERVAL = 300000; // 5 minutes

// Function to get the real client IP address
const getClientIp = (req) => {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
        // 'x-forwarded-for' can be a comma-separated list of IPs. The first one is the original client.
        return forwarded.split(',')[0].trim();
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

    const fetchCrtSh = async () => {
        const res = await fetch(`https://crt.sh/?q=%.${domain}&output=json`);
        if (!res.ok) throw new Error('crt.sh API request failed.');
        const data = await res.json();
        const subdomains = [...new Set(data.map(item => item.name_value.replace(/\\*\\./g, '').toLowerCase()))].sort();
        return subdomains.length > 0 ? subdomains.join('\n') : 'No subdomains found.';
    };

    const fetchVirusTotal = async () => {
        if (!vtApiKey) return 'VirusTotal API Key not set on server.';
        
        const scanUrl = 'https://www.virustotal.com/api/v3/urls';
        const scanOptions = {
            method: 'POST',
            headers: { 'x-apikey': vtApiKey, 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `url=https://${domain}`
        };
        const scanResponse = await fetch(scanUrl, scanOptions);
        if (!scanResponse.ok) throw new Error(`VT Scan Submission Error: ${scanResponse.statusText}`);
        const scanData = await scanResponse.json();
        if (scanData.error) throw new Error(`VT Scan Error: ${scanData.error.message}`);
        const analysisId = scanData.data.id;

        await new Promise(resolve => setTimeout(resolve, 5000));

        const reportUrl = `https://www.virustotal.com/api/v3/analyses/${analysisId}`;
        const reportOptions = { headers: { 'x-apikey': vtApiKey } };
        const reportResponse = await fetch(reportUrl, reportOptions);
        if (!reportResponse.ok) throw new Error(`VT Report Error: ${reportResponse.statusText}`);
        const reportData = await reportResponse.json();
        const stats = reportData.data.attributes.stats;
        return `Malicious: ${stats.malicious}\nSuspicious: ${stats.suspicious}\nHarmless: ${stats.harmless}\nUndetected: ${stats.undetected}`;
    };

    try {
        const [crtShResult, vtResult] = await Promise.allSettled([
            fetchCrtSh(),
            fetchVirusTotal()
        ]);

        const responseData = {
            crtSh: crtShResult.status === 'fulfilled' ? crtShResult.value : `Error: ${crtShResult.reason.message}`,
            virusTotal: vtResult.status === 'fulfilled' ? vtResult.value : `Error: ${vtResult.reason.message}`
        };

        return response.status(200).json(responseData);

    } catch (error) {
        return response.status(500).json({ error: error.message });
    }
}
