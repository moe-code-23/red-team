const ipRequestMap = new Map();
const keyUsageMap = new Map();
const RATE_LIMIT_WINDOW = 60000;
const MAX_REQUESTS_PER_WINDOW = 10;
const IP_CLEANUP_INTERVAL = 300000;
const VT_REQUESTS_PER_MINUTE = 4;

const getVTApiKeys = () => {
    const keys = [];
    for (let i = 1; i <= 5; i++) {
        const key = process.env[`VT_API_KEY_${i}`];
        if (key) keys.push(key);
    }
    return keys.length > 0 ? keys : [process.env.VT_API_KEY].filter(Boolean);
};

const getAvailableVTKey = () => {
    const keys = getVTApiKeys();
    const now = Date.now();
    
    for (const key of keys) {
        if (!keyUsageMap.has(key)) {
            keyUsageMap.set(key, []);
        }
        
        const usage = keyUsageMap.get(key);
        const recentUsage = usage.filter(timestamp => now - timestamp < RATE_LIMIT_WINDOW);
        keyUsageMap.set(key, recentUsage);
        
        if (recentUsage.length < VT_REQUESTS_PER_MINUTE) {
            recentUsage.push(now);
            return key;
        }
    }
    
    return null;
};

const getClientIp = (req) => {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
        return forwarded.split(',')[0].trim();
    }
    return req.socket?.remoteAddress || req.headers['x-real-ip'] || '127.0.0.1';
};

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
    
    for (const [key, timestamps] of keyUsageMap.entries()) {
        const recentTimestamps = timestamps.filter(ts => now - ts < RATE_LIMIT_WINDOW);
        keyUsageMap.set(key, recentTimestamps);
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

    if (!domain) {
        return response.status(400).json({ error: 'Domain is required' });
    }

    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/;
    if (!domainRegex.test(domain)) {
        return response.status(400).json({ error: 'Invalid domain format' });
    }

    const fetchCrtSh = async () => {
        const res = await fetch(`https://crt.sh/?q=%.${domain}&output=json`);
        if (!res.ok) throw new Error('crt.sh API request failed.');
        const data = await res.json();
        const subdomains = [...new Set(data.map(item => item.name_value.replace(/\*\./g, '').toLowerCase()))].sort();
        return subdomains.length > 0 ? subdomains.join('\n') : 'No subdomains found.';
    };

    const fetchVirusTotal = async () => {
        const vtApiKey = getAvailableVTKey();
        if (!vtApiKey) return 'All VirusTotal API keys exhausted. Try again in a minute.';
        
        try {
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
        } catch (error) {
            throw error;
        }
    };

    const fetchShodan = async () => {
        const shodanApiKey = process.env.SHODAN_API_KEY;
        if (!shodanApiKey) return 'Shodan API Key not configured.';
        
        try {
            const res = await fetch(`https://api.shodan.io/shodan/host/search?key=${shodanApiKey}&query=hostname:${domain}`);
            if (!res.ok) throw new Error('Shodan API request failed.');
            const data = await res.json();
            
            if (data.matches && data.matches.length > 0) {
                const results = data.matches.slice(0, 5).map(match => 
                    `${match.ip_str}:${match.port} - ${match.product || 'Unknown'}`
                ).join('\n');
                return `Found ${data.total} results:\n${results}`;
            }
            return 'No Shodan results found.';
        } catch (error) {
            throw error;
        }
    };

    try {
        const [crtShResult, vtResult, shodanResult] = await Promise.allSettled([
            fetchCrtSh(),
            fetchVirusTotal(),
            fetchShodan()
        ]);

        const responseData = {
            crtSh: crtShResult.status === 'fulfilled' ? crtShResult.value : `Error: ${crtShResult.reason.message}`,
            virusTotal: vtResult.status === 'fulfilled' ? vtResult.value : `Error: ${vtResult.reason.message}`,
            shodan: shodanResult.status === 'fulfilled' ? shodanResult.value : `Error: ${shodanResult.reason.message}`
        };

        return response.status(200).json(responseData);

    } catch (error) {
        return response.status(500).json({ error: error.message });
    }
}
