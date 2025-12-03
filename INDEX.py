"""
╔════════════════════════════════════════════════════════════════╗
║           HACKING TOOLS SUITE - COMPLETE INDEX                 ║
║              Educational Security Tools v1.0                   ║
╚════════════════════════════════════════════════════════════════╝

PROJECT STRUCTURE
=================

Hacking Tools/
│
├── hacking_tools/                    Main package
│   ├── __init__.py                  Package initialization
│   ├── launcher.py                  ⭐ Main interactive launcher
│   │
│   ├── network_tools/               🌐 Network reconnaissance
│   │   ├── __init__.py
│   │   ├── port_scanner.py          Scan for open ports
│   │   └── network_mapper.py        Discover active hosts
│   │
│   ├── cryptography_tools/          🔐 Encryption & hashing
│   │   ├── __init__.py
│   │   └── cipher_tools.py          Caesar, Vigenère, Base64, Hashing
│   │
│   ├── web_security/                🌐 Web vulnerability testing
│   │   ├── __init__.py
│   │   └── injection_tester.py      SQL Injection & XSS detection
│   │
│   ├── password_tools/              🔑 Password analysis
│   │   ├── __init__.py
│   │   └── password_analyzer.py     Strength analysis & hash cracking
│   │
│   ├── packet_analysis/             📦 Network packet inspection
│   │   ├── __init__.py
│   │   └── packet_sniffer.py        Capture & analyze packets
│   │
│   └── social_engineering/          ⚠️  Phishing & awareness
│       ├── __init__.py
│       └── phishing_detector.py     Detect phishing attempts
│
├── README.md                        📖 Full documentation
├── QUICKSTART.py                    🚀 Quick start guide
├── SETUP.py                         ⚙️  Setup instructions
└── requirements.txt                 📦 Python dependencies


QUICK REFERENCE
===============

LAUNCHING TOOLS
───────────────
Option 1: Interactive Menu
  python hacking_tools/launcher.py

Option 2: Direct Tool Execution
  python hacking_tools/network_tools/port_scanner.py --help
  python hacking_tools/cryptography_tools/cipher_tools.py
  python hacking_tools/web_security/injection_tester.py
  python hacking_tools/password_tools/password_analyzer.py
  python hacking_tools/packet_analysis/packet_sniffer.py
  python hacking_tools/social_engineering/phishing_detector.py


TOOL COMMANDS
═════════════

1. PORT SCANNER
  ─────────────
  Syntax: python network_tools/port_scanner.py <target> [--ports RANGE] [--timeout N] [--threads N]
  
  Examples:
    python network_tools/port_scanner.py localhost
    python network_tools/port_scanner.py 192.168.1.1 --ports 1-1000
    python network_tools/port_scanner.py example.com --ports 80,443,8080 --threads 100
    python network_tools/port_scanner.py 10.0.0.1 --ports 1-10000 --timeout 2


2. NETWORK MAPPER
  ────────────────
  Syntax: python network_tools/network_mapper.py <network> [--timeout N] [--threads N]
  
  Examples:
    python network_tools/network_mapper.py 192.168.1.0/24
    python network_tools/network_mapper.py 10.0.0.0/24 --timeout 3
    python network_tools/network_mapper.py 172.16.0.0/24 --threads 100


3. CIPHER TOOLS
  ──────────────
  Syntax: python cryptography_tools/cipher_tools.py
  
  Usage:
    # Interactive demo with examples
    python cryptography_tools/cipher_tools.py
    
  Features:
    - Caesar Cipher (with brute force)
    - Vigenère Cipher
    - Base64 Encoding/Decoding
    - MD5, SHA1, SHA256, SHA512 Hashing


4. INJECTION TESTER
  ──────────────────
  Syntax: python web_security/injection_tester.py
  
  Usage:
    # Interactive demo showing:
    python web_security/injection_tester.py
    
  Tests:
    - SQL Injection patterns
    - XSS vulnerabilities
    - Input sanitization
    - HTML entity encoding


5. PASSWORD ANALYZER
  ───────────────────
  Syntax: python password_tools/password_analyzer.py
  
  Usage:
    # Interactive demo showing:
    python password_tools/password_analyzer.py
    
  Features:
    - Password strength scoring
    - Entropy calculation
    - Dictionary attack demonstration
    - MD5/SHA256 hash cracking


6. PACKET SNIFFER
  ────────────────
  Syntax: python packet_analysis/packet_sniffer.py [--interface IFACE] [--count N] [--filter FILTER]
  
  ⚠️  REQUIRES ADMINISTRATOR/ROOT PRIVILEGES
  
  Examples:
    python packet_analysis/packet_sniffer.py --count 10
    python packet_analysis/packet_sniffer.py --interface eth0
    python packet_analysis/packet_sniffer.py --filter "tcp port 80"
    python packet_analysis/packet_sniffer.py --filter "ip src 192.168.1.1"


7. PHISHING DETECTOR
  ───────────────────
  Syntax: python social_engineering/phishing_detector.py
  
  Usage:
    # Interactive demo showing:
    python social_engineering/phishing_detector.py
    
  Features:
    - Email phishing analysis
    - URL threat detection
    - Security awareness tips


PYTHON API USAGE
════════════════

Instead of running tools directly, import them in your Python code:

from hacking_tools.network_tools.port_scanner import PortScanner
from hacking_tools.cryptography_tools.cipher_tools import CaesarCipher, HashTools
from hacking_tools.web_security.injection_tester import SQLInjectionTester
from hacking_tools.password_tools.password_analyzer import PasswordStrengthAnalyzer
from hacking_tools.social_engineering.phishing_detector import PhishingDetector

# Example: Port Scanning
scanner = PortScanner("192.168.1.1", timeout=1)
scanner.scan_range(1, 1000, threads=50)

# Example: Encryption
encrypted = CaesarCipher.encrypt("HELLO WORLD", 3)
hash_value = HashTools.sha256("password123")

# Example: Vulnerability Testing
vuln_report = SQLInjectionTester.generate_test_report("' OR '1'='1")

# Example: Password Analysis
pwd_analysis = PasswordStrengthAnalyzer.analyze("MyP@ssw0rd!")


INSTALLATION
════════════

1. Install dependencies:
   pip install -r requirements.txt

2. Verify installation:
   python -c "import scapy, requests, bs4; print('✓ Ready')"

3. Run tools:
   python hacking_tools/launcher.py


SYSTEM REQUIREMENTS
═══════════════════

✓ Python 3.7 or higher
✓ Windows/Linux/macOS
✓ Administrator privileges (for packet sniffer)
✓ Target permissions (for network scanning)

Core Dependencies:
  - requests (HTTP library)
  - beautifulsoup4 (Web scraping)
  - scapy (Packet manipulation)
  - paramiko (SSH/SFTP)


FEATURE MATRIX
══════════════

Tool                    Network  Crypto  WebSec  Passwd  Network  Social
────────────────────────────────────────────────────────────────────────
Port Scanner              ✓                              ✓
Network Mapper            ✓                              ✓
Cipher Tools                      ✓
Injection Tester                          ✓
Password Analyzer                                  ✓
Packet Sniffer                                           ✓
Phishing Detector                                                 ✓


LEARNING PATH
═════════════

Beginner:
  1. Start with QUICKSTART.py
  2. Run Cipher Tools - understand encryption
  3. Run Injection Tester - learn about vulnerabilities
  4. Run Password Analyzer - understand security

Intermediate:
  1. Run Port Scanner - scan localhost
  2. Run Network Mapper - map your network
  3. Run Phishing Detector - learn about threats
  4. Read source code of each tool

Advanced:
  1. Modify tools for specific use cases
  2. Combine tools for complex attacks
  3. Deploy on dedicated testing environments
  4. Implement additional features


COMMON COMMANDS CHEAT SHEET
════════════════════════════

# Start interactive launcher
python hacking_tools/launcher.py

# Scan localhost for open ports
python hacking_tools/network_tools/port_scanner.py localhost --ports 1-10000

# Encrypt text using Caesar cipher
python -c "from hacking_tools.cryptography_tools.cipher_tools import CaesarCipher; print(CaesarCipher.encrypt('HELLO', 3))"

# Generate SHA256 hash
python -c "from hacking_tools.cryptography_tools.cipher_tools import HashTools; print(HashTools.sha256('password'))"

# Test SQL Injection vulnerability
python hacking_tools/web_security/injection_tester.py

# Analyze password strength
python hacking_tools/password_tools/password_analyzer.py

# Capture 20 network packets
python hacking_tools/packet_analysis/packet_sniffer.py --count 20

# Detect phishing in email
python hacking_tools/social_engineering/phishing_detector.py


ETHICAL GUIDELINES
═══════════════════

✓ DO:
  • Use on systems you own
  • Get written permission before testing
  • Practice in controlled environments
  • Report vulnerabilities responsibly
  • Share knowledge with others
  • Follow local laws

✗ DON'T:
  • Hack systems without permission
  • Use for malicious purposes
  • Bypass security without authorization
  • Disrupt production systems
  • Share exploits publicly
  • Break the law


TROUBLESHOOTING
═══════════════

Issue: "ModuleNotFoundError: No module named 'scapy'"
→ Solution: pip install scapy

Issue: "Permission denied" on packet sniffer
→ Solution: Run as Administrator (Windows) or use sudo (Linux/macOS)

Issue: "Connection refused" on port scan
→ Solution: Ensure target is reachable and firewall allows ICMP

Issue: Import errors
→ Solution: Verify you're in correct directory and all dependencies installed

Issue: Network mapper shows no hosts
→ Solution: Ensure network range is correct and hosts are online


DOCUMENTATION
══════════════

Full Documentation:          README.md
Quick Start Guide:           QUICKSTART.py
Setup Instructions:          SETUP.py
Requirements:                requirements.txt


RESOURCES
════════════

Learning Platforms:
  • TryHackMe: https://tryhackme.com/
  • HackTheBox: https://www.hackthebox.com/
  • OWASP: https://owasp.org/

Security Communities:
  • Reddit: r/cybersecurity
  • Discord: Cybersecurity servers
  • GitHub: Security projects


SUPPORT & CONTACT
═════════════════

For tool documentation: See individual --help flags
For Python API help: Read source code docstrings
For errors: Check troubleshooting section above
For questions: Refer to README.md


VERSION INFORMATION
════════════════════

Suite Version: 1.0.0
Python: 3.7+
Status: Educational Use Only


═════════════════════════════════════════════════════════════════

⚖️  LEGAL NOTICE ⚖️

These tools are provided for EDUCATIONAL PURPOSES ONLY.
Unauthorized access to computer systems is ILLEGAL.
Only use on systems you own or have explicit permission to test.

The creators are not responsible for misuse of these tools.

Stay ethical. Stay legal. Keep learning.

═════════════════════════════════════════════════════════════════
"""

if __name__ == '__main__':
    print(__doc__)
    
    print("\n" + "="*60)
    print("Quick Access:")
    print("="*60)
    print("1. Read documentation:      python README.md")
    print("2. Quick start guide:       python QUICKSTART.py")
    print("3. Setup instructions:      python SETUP.py")
    print("4. Launch interactive menu: python hacking_tools/launcher.py")
    print("="*60)
