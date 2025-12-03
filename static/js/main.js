// Hacking Tools Suite - Main JavaScript

let allTools = [];
let currentTool = null;

// Initialize application
document.addEventListener('DOMContentLoaded', function() {
    loadTools();
    setupEventListeners();
    showWelcomeScreen();
});

// Load tools from API
async function loadTools() {
    try {
        const response = await fetch('/api/tools');
        allTools = await response.json();
        renderToolList(allTools);
    } catch (error) {
        console.error('Error loading tools:', error);
        showError('Failed to load tools');
    }
}

// Render tool list in sidebar
function renderToolList(tools) {
    const toolList = document.getElementById('tool-list');
    toolList.innerHTML = '';
    
    tools.forEach(tool => {
        const toolItem = document.createElement('div');
        toolItem.className = 'tool-item';
        toolItem.id = `tool-${tool.id}`;
        toolItem.innerHTML = `
            <div style="display: flex; align-items: center; gap: 10px;">
                <span class="tool-item-icon" style="font-size: 20px;">${tool.icon}</span>
                <div>
                    <div class="tool-item-name" style="font-weight: 600; margin-bottom: 2px; font-size: 14px;">${tool.name}</div>
                    <div class="tool-item-desc" style="font-size: 11px; opacity: 0.75;">${tool.description}</div>
                </div>
            </div>
        `;
        toolItem.onclick = (e) => {
            e.stopPropagation();
            showTool(tool, toolItem);
        };
        toolList.appendChild(toolItem);
    });
}

// Show selected tool
function showTool(tool, toolItem) {
    if (!tool || !tool.id) {
        console.error('Invalid tool:', tool);
        return;
    }
    
    currentTool = tool;
    
    // Update active state in sidebar
    document.querySelectorAll('.tool-item').forEach(item => {
        item.classList.remove('active');
    });
    
    if (toolItem) {
        toolItem.classList.add('active');
    } else {
        const item = document.getElementById(`tool-${tool.id}`);
        if (item) item.classList.add('active');
    }
    
    // Hide welcome screen - explicitly set display to none
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
        default:
            content = '<p>Tool not found</p>';
    }
    
    panel.innerHTML = content;
    return panel;
}

// Port Scanner Panel
function createPortScannerPanel() {
    return `
        <h2>🌐 Port Scanner</h2>
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
        <h2>🔐 Caesar Cipher</h2>
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
        <h2>🔐 Vigenère Cipher</h2>
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
        <h2>🔐 Base64 Encoder/Decoder</h2>
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
        <h2>🔐 Hash Generator</h2>
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
        <h2>🎯 SQL Injection Tester</h2>
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
        <h2>🎯 XSS Vulnerability Tester</h2>
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
        <h2>🔑 Password Strength Analyzer</h2>
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
        <h2>⚠️ Phishing Detector</h2>
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
    // Category filters
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const category = this.getAttribute('data-category');
            
            document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            
            if (category === 'all') {
                renderToolList(allTools);
            } else {
                const filtered = allTools.filter(t => t.category === category);
                renderToolList(filtered);
            }
        });
    });
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
            <h2>📡 WiFi Network Scanner</h2>
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
            <h2>🔒 WiFi Security Analyzer</h2>
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
            <h2>📊 WiFi Channel Analyzer</h2>
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
            <h2>🔍 WiFi Connection Analyzer</h2>
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
                </div>
            </div>
        `;
        
        if (data.connection_history.length > 0) {
            html += `
                <div class="result-box" style="border-left-color: #4299e1; margin-top: 20px;">
                    <h3>Connection History:</h3>
                    <ul style="margin-top: 10px;">
            `;
            
            data.connection_history.forEach(conn => {
                html += `<li style="padding: 8px; color: #cbd5e0;">${conn.name}</li>`;
            });
            
            html += `
                    </ul>
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
            <h2>🔑 WiFi Password Analyzer</h2>
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
            <h2>⚠️ WiFi Security Vulnerability Test</h2>
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
            <h2>🗺️ Network Mapping</h2>
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
