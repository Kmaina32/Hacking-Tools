"""
Hacking Tools Web Application
==============================
Flask-based web interface for all security tools.
Access at: http://localhost:5000
"""

from flask import Flask, render_template, request, jsonify, send_file
import json
import os
from datetime import datetime
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

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

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# Store scan results in memory
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
            'icon': '🌐',
            'description': 'Scan for open ports on a target host',
            'category': 'Network'
        },
        {
            'id': 'caesar_cipher',
            'name': 'Caesar Cipher',
            'icon': '🔐',
            'description': 'Encrypt/decrypt with Caesar cipher',
            'category': 'Cryptography'
        },
        {
            'id': 'vigenere_cipher',
            'name': 'Vigenère Cipher',
            'icon': '🔐',
            'description': 'Polyalphabetic encryption',
            'category': 'Cryptography'
        },
        {
            'id': 'base64_cipher',
            'name': 'Base64 Encoder',
            'icon': '🔐',
            'description': 'Base64 encoding/decoding',
            'category': 'Cryptography'
        },
        {
            'id': 'hash_tools',
            'name': 'Hash Generator',
            'icon': '🔐',
            'description': 'Generate MD5, SHA1, SHA256, SHA512 hashes',
            'category': 'Cryptography'
        },
        {
            'id': 'sql_injection',
            'name': 'SQL Injection Tester',
            'icon': '🎯',
            'description': 'Test for SQL injection vulnerabilities',
            'category': 'Web Security'
        },
        {
            'id': 'xss_tester',
            'name': 'XSS Vulnerability Tester',
            'icon': '🎯',
            'description': 'Detect XSS attack vectors',
            'category': 'Web Security'
        },
        {
            'id': 'password_strength',
            'name': 'Password Strength Analyzer',
            'icon': '🔑',
            'description': 'Analyze password strength and entropy',
            'category': 'Password'
        },
        {
            'id': 'phishing_detector',
            'name': 'Phishing Detector',
            'icon': '⚠️',
            'description': 'Detect phishing emails and URLs',
            'category': 'Social Engineering'
        },
        {
            'id': 'wifi_scanner',
            'name': 'WiFi Scanner',
            'icon': '📡',
            'description': 'Scan available WiFi networks',
            'category': 'Network'
        },
        {
            'id': 'wifi_security',
            'name': 'WiFi Security Analyzer',
            'icon': '🔒',
            'description': 'Analyze WiFi network security',
            'category': 'Network'
        },
        {
            'id': 'channel_analyzer',
            'name': 'WiFi Channel Analyzer',
            'icon': '📊',
            'description': 'Analyze WiFi channels and interference',
            'category': 'Network'
        },
        {
            'id': 'wifi_connection_analyzer',
            'name': 'Connection Analyzer',
            'icon': '🔍',
            'description': 'Analyze current WiFi connection details',
            'category': 'Network'
        },
        {
            'id': 'wifi_password_analyzer',
            'name': 'Password Strength Analyzer',
            'icon': '🔑',
            'description': 'Analyze WiFi password strength',
            'category': 'Network'
        },
        {
            'id': 'wifi_security_test',
            'name': 'Security Vulnerability Test',
            'icon': '⚠️',
            'description': 'Test for WiFi security vulnerabilities',
            'category': 'Network'
        },
        {
            'id': 'network_mapping',
            'name': 'Network Mapping',
            'icon': '🗺️',
            'description': 'Map nearby WiFi networks',
            'category': 'Network'
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
        
        return jsonify({
            'networks': networks,
            'current_network': current,
            'total_networks': len(networks)
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
        
        return jsonify({
            'connection_info': info,
            'connection_history': history
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


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    return jsonify({'error': 'Internal server error'}), 500


def create_app():
    """Create and configure the Flask app."""
    return app


if __name__ == '__main__':
    print("""
    ╔════════════════════════════════════════════════════════════╗
    ║     HACKING TOOLS WEB APPLICATION - STARTING               ║
    ╚════════════════════════════════════════════════════════════╝
    
    📍 Access the application at: http://localhost:5000
    
    Available Tools:
      🌐 Port Scanner
      📡 WiFi Scanner
      🔒 WiFi Security Analyzer
      📊 WiFi Channel Analyzer
      🔍 Connection Analyzer (NEW)
      🔑 Password Analyzer (NEW)
      ⚠️  Security Vulnerability Tester (NEW)
      🗺️  Network Mapping (NEW)
      🔐 Cipher Tools (Caesar, Vigenère, Base64, Hashing)
      🎯 Injection Tester (SQL & XSS)
      🔑 Password Strength Analyzer
      ⚠️  Phishing Detector
    
    Press Ctrl+C to stop the server
    ════════════════════════════════════════════════════════════
    """)
    
    app.run(debug=True, host='localhost', port=5000)
