const ipRequestMap = new Map();
const RATE_LIMIT_WINDOW = 60000; // 1 minute in milliseconds
const MAX_REQUESTS_PER_WINDOW = 10; // Allow 10 requests per minute per user

export default async function handler(request, response) {
    const ip = request.headers['x-forwarded-for'] || '127.0.0.1';
    const now = Date.now();

    if (!ipRequestMap.has(ip)) {
        ipRequestMap.set(ip, []);
    }

    const requests = ipRequestMap.get(ip).filter(timestamp => now - timestamp < RATE_LIMIT_WINDOW);
    ipRequestMap.set(ip, requests);

    if (requests.length >= MAX_REQUESTS_PER_WINDOW) {
        return response.status(429).json({ error: 'Rate limit exceeded. Please try again in a minute.' });
    }
    
    requests.push(now);
    ipRequestMap.set(ip, requests);

    const domain = request.query.domain;
    const vtApiKey = process.env.VT_API_KEY;

    if (!domain) {
        return response.status(400).json({ error: 'Domain is required' });
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