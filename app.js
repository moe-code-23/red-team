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

    const initPayloadGenerator = () => { /* Existing Payload Generator Code */ };
    const initDataConverter = () => { /* Existing Data Converter Code */ };

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
            progressText.textContent = message;
            progressBar.style.width = isLoading ? '0%' : '100%';
        };

        const updateProgress = (percentage, message) => {
            progressBar.style.width = `${percentage}%`;
            progressText.textContent = message;
        };

        const renderGraph = (nodes, edges) => {
            const data = { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) };
            const options = {
                nodes: {
                    shape: 'dot',
                    size: 16,
                    font: { color: '#e6edf3', size: 14 },
                    borderWidth: 2,
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
