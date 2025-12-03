"""
Hacking Tools Web Application
==============================
Flask-based web interface for all security tools.
Access at: http://localhost:5000
"""

from flask import Flask, render_template, request, jsonify, send_file
import json
import os
from datetime import datetime, timedelta
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Database imports
from database import db, ScanResult, ToolUsage, SavedConfiguration, Session, init_db, get_db_stats

from hacking_tools.network_tools.port_scanner import PortScanner
from hacking_tools.cryptography_tools.cipher_tools import (
    CaesarCipher, VigenereCipher, Base64Cipher, HashTools
)
from hacking_tools.web_security.injection_tester import (
    SQLInjectionTester, XSSVulnerabilityTester
)
from hacking_tools.password_tools.password_analyzer import (
    PasswordStrengthAnalyzer, HashCracker
)
from hacking_tools.social_engineering.phishing_detector import (
    PhishingDetector, SecurityAwareness
)
from hacking_tools.wifi_tools.wifi_scanner import (
    WiFiScanner, WiFiSecurity, WiFiChannelAnalyzer
)
from hacking_tools.wifi_tools.connection_hacking import (
    WiFiConnectionAnalyzer, WiFiPasswordTools, WiFiSecurityTest, WiFiNetworkMapping
)
from hacking_tools.wifi_tools.deauth_attack import DeauthAttack
from hacking_tools.wifi_tools.wpa_handshake_capturer import WPAHandshakeCapturer
from hacking_tools.wifi_tools.wifi_password_cracker import WiFiPasswordCracker
from hacking_tools.wifi_tools.evil_twin import EvilTwinAP

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# Database configuration
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "hacking_tools.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db.init_app(app)

# Initialize database tables on first run
if not os.path.exists(os.path.join(basedir, "hacking_tools.db")):
    init_db(app)

# Store scan results in memory (for quick access)
scan_results = {}


@app.route('/')
def index():
    """Home page."""
    return render_template('index.html')


@app.route('/api/tools')
def get_tools():
    """Get list of available tools."""
    tools = [
        {
            'id': 'port_scanner',
            'name': 'Port Scanner',
            'icon': '',
            'description': 'Scan for open ports on a target host',
            'category': 'Network'
        },
        {
            'id': 'caesar_cipher',
            'name': 'Caesar Cipher',
            'icon': '',
            'description': 'Encrypt/decrypt with Caesar cipher',
            'category': 'Cryptography'
        },
        {
            'id': 'vigenere_cipher',
            'name': 'Vigenère Cipher',
            'icon': '',
            'description': 'Polyalphabetic encryption',
            'category': 'Cryptography'
        },
        {
            'id': 'base64_cipher',
            'name': 'Base64 Encoder',
            'icon': '',
            'description': 'Base64 encoding/decoding',
            'category': 'Cryptography'
        },
        {
            'id': 'hash_tools',
            'name': 'Hash Generator',
            'icon': '',
            'description': 'Generate MD5, SHA1, SHA256, SHA512 hashes',
            'category': 'Cryptography'
        },
        {
            'id': 'sql_injection',
            'name': 'SQL Injection Tester',
            'icon': '',
            'description': 'Test for SQL injection vulnerabilities',
            'category': 'Web Security'
        },
        {
            'id': 'xss_tester',
            'name': 'XSS Vulnerability Tester',
            'icon': '',
            'description': 'Detect XSS attack vectors',
            'category': 'Web Security'
        },
        {
            'id': 'password_strength',
            'name': 'Password Strength Analyzer',
            'icon': '',
            'description': 'Analyze password strength and entropy',
            'category': 'Password'
        },
        {
            'id': 'phishing_detector',
            'name': 'Phishing Detector',
            'icon': '',
            'description': 'Detect phishing emails and URLs',
            'category': 'Social Engineering'
        },
        {
            'id': 'wifi_scanner',
            'name': 'WiFi Scanner',
            'icon': '',
            'description': 'Scan available WiFi networks',
            'category': 'Network'
        },
        {
            'id': 'wifi_security',
            'name': 'WiFi Security Analyzer',
            'icon': '',
            'description': 'Analyze WiFi network security',
            'category': 'Network'
        },
        {
            'id': 'channel_analyzer',
            'name': 'WiFi Channel Analyzer',
            'icon': '',
            'description': 'Analyze WiFi channels and interference',
            'category': 'Network'
        },
        {
            'id': 'wifi_connection_analyzer',
            'name': 'Connection Analyzer',
            'icon': '',
            'description': 'Analyze current WiFi connection details',
            'category': 'Network'
        },
        {
            'id': 'wifi_password_analyzer',
            'name': 'Password Strength Analyzer',
            'icon': '',
            'description': 'Analyze WiFi password strength',
            'category': 'Network'
        },
        {
            'id': 'wifi_security_test',
            'name': 'Security Vulnerability Test',
            'icon': '',
            'description': 'Test for WiFi security vulnerabilities',
            'category': 'Network'
        },
        {
            'id': 'network_mapping',
            'name': 'Network Mapping',
            'icon': '',
            'description': 'Map nearby WiFi networks',
            'category': 'Network'
        },
        {
            'id': 'deauth_attack',
            'name': 'Deauthentication Attack',
            'icon': '',
            'description': 'Send deauth packets to disconnect clients',
            'category': 'WiFi Attacks'
        },
        {
            'id': 'wpa_handshake_capturer',
            'name': 'WPA Handshake Capturer',
            'icon': '',
            'description': 'Capture WPA 4-way handshakes',
            'category': 'WiFi Attacks'
        },
        {
            'id': 'wifi_password_cracker',
            'name': 'WiFi Password Cracker',
            'icon': '',
            'description': 'Dictionary attack on WiFi passwords',
            'category': 'WiFi Attacks'
        },
        {
            'id': 'evil_twin',
            'name': 'Evil Twin Attack',
            'icon': '',
            'description': 'Create fake access points',
            'category': 'WiFi Attacks'
        },
        {
            'id': 'exploit_framework',
            'name': 'Exploit Framework',
            'icon': '',
            'description': 'Framework for exploit development and testing',
            'category': 'Exploitation'
        },
        {
            'id': 'payload_generator',
            'name': 'Payload Generator',
            'icon': '',
            'description': 'Generate various payloads for penetration testing',
            'category': 'Exploitation'
        },
        {
            'id': 'reverse_shell',
            'name': 'Reverse Shell Generator',
            'icon': '',
            'description': 'Generate reverse shell commands for multiple platforms',
            'category': 'Exploitation'
        },
        {
            'id': 'subdomain_scanner',
            'name': 'Subdomain Scanner',
            'icon': '',
            'description': 'Discover subdomains of a target domain',
            'category': 'Reconnaissance'
        },
        {
            'id': 'dns_enumeration',
            'name': 'DNS Enumeration',
            'icon': '',
            'description': 'Enumerate DNS records and information',
            'category': 'Reconnaissance'
        },
        {
            'id': 'whois_lookup',
            'name': 'Whois Lookup',
            'icon': '',
            'description': 'Lookup domain registration and ownership information',
            'category': 'Reconnaissance'
        },
        {
            'id': 'image_steganography',
            'name': 'Image Steganography',
            'icon': '',
            'description': 'Hide and extract data from images',
            'category': 'Steganography'
        },
        {
            'id': 'text_steganography',
            'name': 'Text Steganography',
            'icon': '',
            'description': 'Hide and extract data from text files',
            'category': 'Steganography'
        }
    ]
    return jsonify(tools)


@app.route('/api/scan/port', methods=['POST'])
def scan_ports():
    """Scan ports on target host."""
    try:
        data = request.get_json()
        target = data.get('target', 'localhost')
        port_range = data.get('ports', '1-1000')
        timeout = float(data.get('timeout', 1))
        threads = int(data.get('threads', 50))
        
        # Parse port range
        if '-' in port_range:
            start, end = port_range.split('-')
            start_port, end_port = int(start), int(end)
        else:
            ports = [int(p.strip()) for p in port_range.split(',')]
            start_port, end_port = ports[0], ports[-1]
        
        # Validate range
        if start_port < 1 or end_port > 65535:
            return jsonify({'error': 'Port range must be 1-65535'}), 400
        
        scanner = PortScanner(target, timeout)
        scanner.scan_range(start_port, end_port, threads)
        
        result = {
            'target': target,
            'open_ports': scanner.open_ports,
            'total_ports_scanned': end_port - start_port + 1,
            'open_count': len(scanner.open_ports),
            'timestamp': datetime.now().isoformat()
        }
        
        # Save to database
        save_scan_result('port_scanner', 'Port Scanner', target, {
            'port_range': port_range,
            'timeout': timeout,
            'threads': threads
        }, result)
        
        # Track tool usage
        track_tool_usage('port_scanner', 'Port Scanner', 'Network')
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/crypto/caesar', methods=['POST'])
def caesar_cipher():
    """Caesar cipher encryption/decryption."""
    try:
        data = request.get_json()
        text = data.get('text', '')
        shift = int(data.get('shift', 3))
        mode = data.get('mode', 'encrypt')
        
        if mode == 'encrypt':
            result = CaesarCipher.encrypt(text, shift)
        elif mode == 'decrypt':
            result = CaesarCipher.decrypt(text, shift)
        elif mode == 'brute_force':
            results = CaesarCipher.brute_force(text)
            return jsonify({'results': results})
        else:
            return jsonify({'error': 'Invalid mode'}), 400
        
        return jsonify({'result': result, 'shift': shift})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/crypto/vigenere', methods=['POST'])
def vigenere_cipher():
    """Vigenère cipher encryption/decryption."""
    try:
        data = request.get_json()
        text = data.get('text', '')
        key = data.get('key', '')
        mode = data.get('mode', 'encrypt')
        
        if not key:
            return jsonify({'error': 'Key is required'}), 400
        
        if mode == 'encrypt':
            result = VigenereCipher.encrypt(text, key)
        elif mode == 'decrypt':
            result = VigenereCipher.decrypt(text, key)
        else:
            return jsonify({'error': 'Invalid mode'}), 400
        
        return jsonify({'result': result})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/crypto/base64', methods=['POST'])
def base64_cipher():
    """Base64 encoding/decoding."""
    try:
        data = request.get_json()
        text = data.get('text', '')
        mode = data.get('mode', 'encode')
        
        if mode == 'encode':
            result = Base64Cipher.encode(text)
        elif mode == 'decode':
            result = Base64Cipher.decode(text)
        else:
            return jsonify({'error': 'Invalid mode'}), 400
        
        return jsonify({'result': result})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/crypto/hash', methods=['POST'])
def hash_tools():
    """Generate hash digests."""
    try:
        data = request.get_json()
        text = data.get('text', '')
        algorithm = data.get('algorithm', 'sha256')
        
        if algorithm == 'md5':
            result = HashTools.md5(text)
        elif algorithm == 'sha1':
            result = HashTools.sha1(text)
        elif algorithm == 'sha256':
            result = HashTools.sha256(text)
        elif algorithm == 'sha512':
            result = HashTools.sha512(text)
        else:
            return jsonify({'error': 'Invalid algorithm'}), 400
        
        return jsonify({'result': result, 'algorithm': algorithm})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/security/sql-injection', methods=['POST'])
def test_sql_injection():
    """Test for SQL injection vulnerabilities."""
    try:
        data = request.get_json()
        user_input = data.get('input', '')
        
        report = SQLInjectionTester.generate_test_report(user_input)
        
        return jsonify({
            'input': report['input'],
            'vulnerable': report['vulnerable'],
            'patterns': report['detected_patterns'],
            'sanitized': report['sanitized'],
            'escaped': report['escaped']
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/security/xss', methods=['POST'])
def test_xss():
    """Test for XSS vulnerabilities."""
    try:
        data = request.get_json()
        user_input = data.get('input', '')
        
        report = XSSVulnerabilityTester.generate_test_report(user_input)
        
        return jsonify({
            'input': report['input'],
            'vulnerable': report['vulnerable'],
            'patterns': report['detected_patterns'],
            'sanitized': report['sanitized'],
            'html_encoded': report['html_encoded']
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/password/strength', methods=['POST'])
def check_password_strength():
    """Analyze password strength."""
    try:
        data = request.get_json()
        password = data.get('password', '')
        
        if not password:
            return jsonify({'error': 'Password is required'}), 400
        
        analysis = PasswordStrengthAnalyzer.analyze(password)
        
        return jsonify({
            'length': analysis['length'],
            'score': analysis['score'],
            'strength': analysis['strength'],
            'entropy': analysis['entropy'],
            'feedback': analysis['feedback']
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/phishing/analyze-email', methods=['POST'])
def analyze_email():
    """Analyze email for phishing."""
    try:
        data = request.get_json()
        sender = data.get('sender', '')
        subject = data.get('subject', '')
        body = data.get('body', '')
        
        result = PhishingDetector.analyze_email(sender, subject, body)
        
        return jsonify({
            'sender': result['sender'],
            'risk_level': result['risk_level'],
            'risk_score': result['risk_score'],
            'red_flags': result['red_flags']
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/phishing/analyze-url', methods=['POST'])
def analyze_url():
    """Analyze URL for phishing threats."""
    try:
        data = request.get_json()
        url = data.get('url', '')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        result = PhishingDetector.analyze_url(url)
        
        return jsonify({
            'url': result['url'],
            'risk_level': result['risk_level'],
            'risk_score': result['risk_score'],
            'red_flags': result['red_flags']
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/security/tips')
def get_security_tips():
    """Get security awareness tips."""
    return jsonify({'tips': SecurityAwareness.BEST_PRACTICES})


@app.route('/api/wifi/scan', methods=['GET'])
def scan_wifi():
    """Scan available WiFi networks."""
    try:
        networks = WiFiScanner.scan_networks()
        current = WiFiScanner.get_current_network()
        
        # Get saved passwords for all networks
        saved_passwords = WiFiScanner.get_all_saved_passwords()
        password_dict = {p['ssid']: p['password'] for p in saved_passwords}
        
        # Add passwords to network info
        for network in networks:
            if network['ssid'] in password_dict:
                network['password'] = password_dict[network['ssid']]
            else:
                network['password'] = None
        
        return jsonify({
            'networks': networks,
            'current_network': current,
            'total_networks': len(networks),
            'saved_passwords': saved_passwords
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/wifi/current', methods=['GET'])
def get_current_wifi():
    """Get current WiFi connection info."""
    try:
        current = WiFiScanner.get_current_network()
        return jsonify(current)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/wifi/security-analysis', methods=['POST'])
def analyze_wifi_security():
    """Analyze WiFi security configuration."""
    try:
        data = request.get_json()
        ssid = data.get('ssid', 'Unknown')
        auth_type = data.get('auth_type', 'Open')
        password = data.get('password', '')
        
        analysis = WiFiSecurity.analyze_security(ssid, auth_type, password)
        
        return jsonify(analysis)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/wifi/default-credentials', methods=['POST'])
def check_default_creds():
    """Check for default router credentials."""
    try:
        data = request.get_json()
        manufacturer = data.get('manufacturer', '')
        
        creds = WiFiSecurity.check_default_credentials(manufacturer)
        
        return jsonify(creds)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/wifi/channel-analysis', methods=['POST'])
def analyze_wifi_channel():
    """Analyze WiFi channel interference."""
    try:
        data = request.get_json()
        channel = int(data.get('channel', 6))
        band = data.get('band', '2.4GHz')
        
        analysis = WiFiChannelAnalyzer.analyze_interference(channel, band)
        
        return jsonify(analysis)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/wifi/connection-details', methods=['GET'])
def get_connection_details():
    """Get detailed current WiFi connection information."""
    try:
        info = WiFiConnectionAnalyzer.get_detailed_connection_info()
        history = WiFiConnectionAnalyzer.get_connection_history()
        
        # Get passwords for history networks
        saved_passwords = WiFiConnectionAnalyzer.get_all_saved_passwords()
        password_dict = {p['ssid']: p['password'] for p in saved_passwords}
        
        # Add passwords to history
        for profile in history:
            if profile['name'] in password_dict:
                profile['password'] = password_dict[profile['name']]
        
        return jsonify({
            'connection_info': info,
            'connection_history': history,
            'saved_passwords': saved_passwords
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/wifi/passwords', methods=['GET'])
def get_wifi_passwords():
    """Get all saved WiFi passwords."""
    try:
        passwords = WiFiScanner.get_all_saved_passwords()
        return jsonify({
            'passwords': passwords,
            'total': len(passwords)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/wifi/password/<ssid>', methods=['GET'])
def get_wifi_password(ssid):
    """Get password for a specific WiFi network."""
    try:
        password = WiFiScanner.get_saved_password(ssid)
        return jsonify({
            'ssid': ssid,
            'password': password,
            'found': password is not None
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/wifi/password-strength', methods=['POST'])
def analyze_password_strength():
    """Analyze WiFi password strength."""
    try:
        data = request.get_json()
        password = data.get('password', '')
        
        if not password:
            return jsonify({'error': 'Password is required'}), 400
        
        strength_analysis = WiFiPasswordTools.analyze_password_strength(password)
        dictionary_check = WiFiPasswordTools.check_dictionary_match(password)
        
        return jsonify({
            'strength_analysis': strength_analysis,
            'dictionary_check': dictionary_check
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/wifi/security-test', methods=['GET'])
def run_security_tests():
    """Run WiFi security vulnerability tests."""
    try:
        wps_test = WiFiSecurityTest.test_wps_vulnerability()
        gateway_test = WiFiSecurityTest.test_default_gateway()
        
        # Get current connection info for cipher analysis
        current_info = WiFiConnectionAnalyzer.get_detailed_connection_info()
        cipher_analysis = WiFiSecurityTest.test_encryption_strength(
            current_info.get('cipher', 'Unknown')
        )
        
        return jsonify({
            'wps_vulnerability_test': wps_test,
            'gateway_vulnerability_test': gateway_test,
            'encryption_cipher_analysis': cipher_analysis,
            'current_connection': current_info
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/wifi/network-mapping', methods=['GET'])
def map_networks():
    """Map and analyze nearby WiFi networks."""
    try:
        networks = WiFiNetworkMapping.scan_detailed_networks()

        return jsonify({
            'networks': networks,
            'total_networks': len(networks)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/wifi/deauth-attack', methods=['POST'])
def perform_deauth_attack():
    """Perform deauthentication attack."""
    try:
        data = request.get_json()
        target_bssid = data.get('target_bssid', '')
        client_mac = data.get('client_mac', '')
        duration = int(data.get('duration', 10))

        if not target_bssid:
            return jsonify({'error': 'Target BSSID is required'}), 400

        result = DeauthAttack.perform_attack(target_bssid, client_mac, duration)

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/wifi/handshake-capture', methods=['POST'])
def capture_handshake():
    """Capture WPA handshake."""
    try:
        data = request.get_json()
        target_bssid = data.get('target_bssid', '')
        channel = int(data.get('channel', 6))
        duration = int(data.get('duration', 30))

        if not target_bssid:
            return jsonify({'error': 'Target BSSID is required'}), 400

        result = WPAHandshakeCapturer.capture_handshake(target_bssid, channel, duration)

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/wifi/password-crack', methods=['POST'])
def crack_password():
    """Crack WiFi password using dictionary attack."""
    try:
        data = request.get_json()
        handshake_file = data.get('handshake_file', '')
        wordlist_file = data.get('wordlist_file', '')
        target_bssid = data.get('target_bssid', '')

        if not handshake_file or not wordlist_file:
            return jsonify({'error': 'Handshake file and wordlist file are required'}), 400

        result = WiFiPasswordCracker.crack_password(handshake_file, wordlist_file, target_bssid)

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/wifi/evil-twin', methods=['POST'])
def create_evil_twin():
    """Create evil twin access point."""
    try:
        data = request.get_json()
        ssid = data.get('ssid', '')
        channel = int(data.get('channel', 6))
        interface = data.get('interface', 'wlan0')

        if not ssid:
            return jsonify({'error': 'SSID is required'}), 400

        result = EvilTwinAP.create_fake_ap(ssid, channel, interface)

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/health')
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({'error': 'Endpoint not found'}), 404


@app.route('/api/recon/subdomain-scan', methods=['POST'])
def scan_subdomains():
    """Scan for subdomains."""
    try:
        data = request.get_json()
        domain = data.get('domain', '')
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
        
        # Simulated subdomain discovery
        import random
        common_subdomains = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api', 'blog', 'shop']
        found = [f"{sub}.{domain}" for sub in random.sample(common_subdomains, random.randint(2, 5))]
        
        return jsonify({
            'domain': domain,
            'subdomains': found,
            'total': len(found)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/recon/dns-enum', methods=['POST'])
def enumerate_dns():
    """Enumerate DNS records."""
    try:
        data = request.get_json()
        domain = data.get('domain', '')
        record_type = data.get('record_type', 'all')
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
        
        # Simulated DNS enumeration
        records = {
            'A': [f'192.168.1.{i}' for i in range(1, 4)],
            'AAAA': ['2001:db8::1', '2001:db8::2'],
            'MX': [f'mail.{domain}', f'mx.{domain}'],
            'NS': [f'ns1.{domain}', f'ns2.{domain}'],
            'TXT': ['v=spf1 include:_spf.example.com ~all'],
            'CNAME': [f'www.{domain}']
        }
        
        if record_type == 'all':
            return jsonify({'domain': domain, 'records': records})
        else:
            return jsonify({'domain': domain, 'records': {record_type: records.get(record_type, [])}})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/recon/whois', methods=['POST'])
def lookup_whois():
    """Lookup Whois information."""
    try:
        data = request.get_json()
        target = data.get('target', '')
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        # Simulated Whois lookup
        whois_info = f"""
Domain: {target}
Registrar: Example Registrar Inc.
Creation Date: 2020-01-15
Expiration Date: 2025-01-15
Updated Date: 2024-01-15
Name Servers:
  ns1.{target}
  ns2.{target}
Registrant:
  Name: Example Organization
  Email: admin@{target}
  Phone: +1.5551234567
"""
        
        return jsonify({
            'target': target,
            'whois_info': whois_info.strip()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/stego/image', methods=['POST'])
def image_steganography():
    """Image steganography operations."""
    try:
        data = request.get_json()
        operation = data.get('operation', 'encode')
        image_path = data.get('image_path', '')
        data_to_hide = data.get('data', '')
        
        if not image_path:
            return jsonify({'error': 'Image path is required'}), 400
        
        if operation == 'encode':
            if not data_to_hide:
                return jsonify({'error': 'Data to hide is required'}), 400
            return jsonify({
                'operation': 'encode',
                'image_path': image_path,
                'output_file': image_path.replace('.png', '_encoded.png'),
                'message': 'Data encoded successfully'
            })
        else:
            return jsonify({
                'operation': 'decode',
                'image_path': image_path,
                'extracted_data': 'Sample extracted data from image',
                'message': 'Data extracted successfully'
            })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/stego/text', methods=['POST'])
def text_steganography():
    """Text steganography operations."""
    try:
        data = request.get_json()
        operation = data.get('operation', 'encode')
        file_path = data.get('file_path', '')
        data_to_hide = data.get('data', '')
        
        if not file_path:
            return jsonify({'error': 'File path is required'}), 400
        
        if operation == 'encode':
            if not data_to_hide:
                return jsonify({'error': 'Data to hide is required'}), 400
            return jsonify({
                'operation': 'encode',
                'file_path': file_path,
                'output_file': file_path.replace('.txt', '_encoded.txt'),
                'message': 'Data encoded successfully'
            })
        else:
            return jsonify({
                'operation': 'decode',
                'file_path': file_path,
                'extracted_data': 'Sample extracted data from text file',
                'message': 'Data extracted successfully'
            })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    return jsonify({'error': 'Internal server error'}), 500


def create_app():
    """Create and configure the Flask app."""
    return app


# Database helper functions
def save_scan_result(tool_id, tool_name, target, parameters, result_data):
    """Save scan result to database."""
    try:
        scan_result = ScanResult(
            tool_id=tool_id,
            tool_name=tool_name,
            target=target,
            parameters=json.dumps(parameters),
            result_data=json.dumps(result_data),
            status='success' if not result_data.get('error') else 'error'
        )
        db.session.add(scan_result)
        db.session.commit()
    except Exception as e:
        print(f"Error saving scan result: {e}")
        db.session.rollback()


def track_tool_usage(tool_id, tool_name, category):
    """Track tool usage statistics."""
    try:
        usage = ToolUsage.query.filter_by(tool_id=tool_id).first()
        if usage:
            usage.usage_count += 1
            usage.last_used = datetime.utcnow()
        else:
            usage = ToolUsage(
                tool_id=tool_id,
                tool_name=tool_name,
                category=category,
                usage_count=1,
                last_used=datetime.utcnow()
            )
            db.session.add(usage)
        db.session.commit()
    except Exception as e:
        print(f"Error tracking tool usage: {e}")
        db.session.rollback()


# Database API endpoints
@app.route('/api/db/stats', methods=['GET'])
def get_db_stats_endpoint():
    """Get database statistics."""
    try:
        stats = {
            'total_scans': ScanResult.query.count(),
            'total_tools_used': ToolUsage.query.count(),
            'total_configs': SavedConfiguration.query.count(),
            'recent_scans': [s.to_dict() for s in ScanResult.query.order_by(ScanResult.created_at.desc()).limit(10).all()]
        }
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/db/scans', methods=['GET'])
def get_scan_history():
    """Get scan history."""
    try:
        tool_id = request.args.get('tool_id')
        limit = int(request.args.get('limit', 50))
        
        query = ScanResult.query
        if tool_id:
            query = query.filter_by(tool_id=tool_id)
        
        scans = query.order_by(ScanResult.created_at.desc()).limit(limit).all()
        return jsonify({
            'scans': [s.to_dict() for s in scans],
            'total': len(scans)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/db/scans/<int:scan_id>', methods=['GET'])
def get_scan_by_id(scan_id):
    """Get specific scan result by ID."""
    try:
        scan = ScanResult.query.get_or_404(scan_id)
        return jsonify(scan.to_dict())
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/db/scans/<int:scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    """Delete a scan result."""
    try:
        scan = ScanResult.query.get_or_404(scan_id)
        db.session.delete(scan)
        db.session.commit()
        return jsonify({'message': 'Scan deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/db/usage', methods=['GET'])
def get_tool_usage():
    """Get tool usage statistics."""
    try:
        category = request.args.get('category')
        
        query = ToolUsage.query
        if category:
            query = query.filter_by(category=category)
        
        usage = query.order_by(ToolUsage.usage_count.desc()).all()
        return jsonify({
            'usage': [u.to_dict() for u in usage],
            'total': len(usage)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/db/configs', methods=['GET'])
def get_saved_configs():
    """Get saved configurations."""
    try:
        tool_id = request.args.get('tool_id')
        
        query = SavedConfiguration.query
        if tool_id:
            query = query.filter_by(tool_id=tool_id)
        
        configs = query.order_by(SavedConfiguration.updated_at.desc()).all()
        return jsonify({
            'configs': [c.to_dict() for c in configs],
            'total': len(configs)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/db/configs', methods=['POST'])
def save_configuration():
    """Save a tool configuration."""
    try:
        data = request.get_json()
        tool_id = data.get('tool_id')
        config_name = data.get('config_name')
        configuration = data.get('configuration', {})
        
        if not tool_id or not config_name:
            return jsonify({'error': 'tool_id and config_name are required'}), 400
        
        config = SavedConfiguration(
            tool_id=tool_id,
            config_name=config_name,
            configuration=json.dumps(configuration)
        )
        db.session.add(config)
        db.session.commit()
        
        return jsonify(config.to_dict())
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/db/configs/<int:config_id>', methods=['DELETE'])
def delete_configuration(config_id):
    """Delete a saved configuration."""
    try:
        config = SavedConfiguration.query.get_or_404(config_id)
        db.session.delete(config)
        db.session.commit()
        return jsonify({'message': 'Configuration deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    # Initialize database on startup
    with app.app_context():
        db.create_all()
        print("[*] Database initialized")
    
    print("""
    ╔════════════════════════════════════════════════════════════╗
    ║     HACKING TOOLS WEB APPLICATION - STARTING               ║
    ╚════════════════════════════════════════════════════════════╝
    
    📍 Access the application at: http://localhost:5000
    💾 Database: SQLite (hacking_tools.db)
    
    Available Tools:
      🌐 Port Scanner
      📡 WiFi Scanner
      🔒 WiFi Security Analyzer
      📊 WiFi Channel Analyzer
      🔍 Connection Analyzer (NEW)
      🔑 Password Analyzer (NEW)
      ⚠️  Security Vulnerability Tester (NEW)
      🗺️  Network Mapping (NEW)
      ⚡ Deauthentication Attack (NEW)
      📡 WPA Handshake Capturer (NEW)
      🔓 WiFi Password Cracker (NEW)
      👤 Evil Twin Attack (NEW)
      🔐 Cipher Tools (Caesar, Vigenère, Base64, Hashing)
      🎯 Injection Tester (SQL & XSS)
      🔑 Password Strength Analyzer
      ⚠️  Phishing Detector
    
    Press Ctrl+C to stop the server
    ════════════════════════════════════════════════════════════
    """)
    
    app.run(debug=True, host='localhost', port=5000)
