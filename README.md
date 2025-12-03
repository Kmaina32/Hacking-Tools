# Hacking Tools Suite - Educational Security Tools

A comprehensive collection of **educational** security tools for learning cybersecurity concepts. All tools are designed for learning purposes only.

## ⚠️ IMPORTANT DISCLAIMER

**These tools are for EDUCATIONAL PURPOSES ONLY!**

- Only use on systems **you own** or have **explicit written permission** to test
- Unauthorized access to computer systems is **ILLEGAL**
- Use in controlled educational environments only
- The creators are not responsible for misuse

---

## Tools Included

### 1. **Network Tools**

#### Port Scanner (`port_scanner.py`)
Scans a target host for open ports using socket connections.

**Features:**
- Multi-threaded scanning for speed
- Common port identification
- Customizable port ranges
- Timeout configuration

**Usage:**
```bash
python network_tools/port_scanner.py 192.168.1.1 --ports 1-1000
python network_tools/port_scanner.py example.com --ports 80,443,8080 --threads 100
```

#### Network Mapper (`network_mapper.py`)
Discovers active hosts on a network using ping and ARP.

**Features:**
- Network range scanning (CIDR notation)
- Host discovery with concurrent threads
- Hostname resolution
- Network report generation

**Usage:**
```bash
python network_tools/network_mapper.py 192.168.1.0/24
python network_tools/network_mapper.py 10.0.0.0/24 --timeout 3 --threads 100
```

---

### 2. **Cryptography Tools**

#### Cipher Tools (`cipher_tools.py`)
Educational encryption and decryption utilities.

**Supported Ciphers:**
- **Caesar Cipher**: Simple substitution cipher with shift
- **Vigenère Cipher**: Polyalphabetic substitution cipher
- **Base64**: Encoding/decoding
- **Hashing**: MD5, SHA1, SHA256, SHA512
- **Brute Force**: Attack all Caesar shifts

**Usage:**
```bash
python cryptography_tools/cipher_tools.py
```

**Example:**
```python
from cryptography_tools.cipher_tools import CaesarCipher, VigenereCipher

# Caesar cipher
encrypted = CaesarCipher.encrypt("HELLO WORLD", 3)  # "KHOOR ZRUOG"
decrypted = CaesarCipher.decrypt(encrypted, 3)

# Vigenère cipher
encrypted = VigenereCipher.encrypt("HELLO WORLD", "SECRET")
decrypted = VigenereCipher.decrypt(encrypted, "SECRET")

# Brute force
results = CaesarCipher.brute_force("KHOOR ZRUOG")
```

---

### 3. **Web Security Tools**

#### Injection Tester (`injection_tester.py`)
Tests for SQL Injection and Cross-Site Scripting (XSS) vulnerabilities.

**Features:**
- SQL Injection pattern detection
- XSS payload identification
- Input sanitization
- Proper escaping methods
- Vulnerability reporting

**Usage:**
```bash
python web_security/injection_tester.py
```

**Example:**
```python
from web_security.injection_tester import SQLInjectionTester, XSSVulnerabilityTester

# Test SQL Injection
report = SQLInjectionTester.generate_test_report("' OR '1'='1")

# Test XSS
report = XSSVulnerabilityTester.generate_test_report("<script>alert('XSS')</script>")

# Sanitize input
clean = SQLInjectionTester.sanitize_input("' OR '1'='1")
```

---

### 4. **Password Tools**

#### Password Analyzer (`password_analyzer.py`)
Analyze password strength and perform hash cracking (dictionary attacks).

**Features:**
- Password strength analysis
- Entropy calculation
- Character type checking
- Common pattern detection
- MD5/SHA256 hash cracking
- Dictionary wordlist generation

**Usage:**
```bash
python password_tools/password_analyzer.py
```

**Example:**
```python
from password_tools.password_analyzer import PasswordStrengthAnalyzer, HashCracker

# Analyze password strength
analysis = PasswordStrengthAnalyzer.analyze("MyP@ssw0rd!")
print(f"Strength: {analysis['strength']}")
print(f"Entropy: {analysis['entropy']} bits")

# Crack MD5 hash
found, password = HashCracker.crack_md5("5f4dcc3b5aa765d61d8327deb882cf99")
```

---

### 5. **Packet Analysis**

#### Packet Sniffer (`packet_sniffer.py`)
Capture and analyze network packets in real-time.

**Requirements:** Administrator/root privileges, scapy library

**Features:**
- Real-time packet capture
- Protocol identification (TCP, UDP, DNS, ICMP)
- Payload inspection
- Capture filtering
- Statistics reporting

**Usage:**
```bash
# Requires admin/root privileges
python packet_analysis/packet_sniffer.py --count 10
python packet_analysis/packet_sniffer.py --filter "tcp port 80"
python packet_analysis/packet_sniffer.py --interface eth0 --filter "ip src 192.168.1.1"
```

---

### 6. **Social Engineering Tools**

#### Phishing Detector (`phishing_detector.py`)
Detect phishing indicators and raise security awareness.

**Features:**
- Email phishing analysis
- URL threat detection
- Suspicious domain identification
- Homograph attack detection
- Red flag reporting
- Security awareness tips

**Usage:**
```bash
python social_engineering/phishing_detector.py
```

**Example:**
```python
from social_engineering.phishing_detector import PhishingDetector

# Analyze email
result = PhishingDetector.analyze_email(
    sender="noreply@paypa1.com",
    subject="URGENT: Verify Account",
    body="Click here to verify your account..."
)
print(f"Risk Level: {result['risk_level']}")

# Analyze URL
result = PhishingDetector.analyze_url("https://amaz0n-security.com/verify")
```

---

## Installation

### Prerequisites
- Python 3.7+
- Windows/Linux/macOS

### Setup

1. **Clone or download the tools:**
```bash
cd "C:\Users\Engineer Kairo Maina\Desktop\Hacking Tools"
```

2. **Install required packages:**
```bash
pip install requests bs4 scapy paramiko
```

3. **Run the launcher:**
```bash
python hacking_tools/launcher.py
```

Or run individual tools directly:
```bash
python hacking_tools/network_tools/port_scanner.py --help
python hacking_tools/cryptography_tools/cipher_tools.py
python hacking_tools/web_security/injection_tester.py
```

---

## Project Structure

```
hacking_tools/
├── __init__.py
├── launcher.py                 # Main launcher
├── network_tools/
│   ├── port_scanner.py         # Port scanning tool
│   └── network_mapper.py        # Network discovery tool
├── cryptography_tools/
│   └── cipher_tools.py          # Encryption/decryption utilities
├── web_security/
│   └── injection_tester.py      # SQL Injection and XSS tester
├── password_tools/
│   └── password_analyzer.py     # Password strength and hash cracking
├── packet_analysis/
│   └── packet_sniffer.py        # Packet capture and analysis
└── social_engineering/
    └── phishing_detector.py     # Phishing detection and awareness
```

---

## Learning Objectives

This suite teaches:

1. **Network Security**
   - How port scanning works
   - Network topology discovery
   - Service identification

2. **Cryptography**
   - Classical cipher techniques
   - Hash functions
   - Encryption/decryption methods

3. **Web Security**
   - SQL Injection techniques
   - XSS vulnerabilities
   - Input validation importance

4. **Password Security**
   - Password entropy
   - Strength requirements
   - Hash cracking methods

5. **Network Analysis**
   - Packet structure
   - Protocol understanding
   - Traffic analysis

6. **Social Engineering**
   - Phishing techniques
   - Email threats
   - URL spoofing

---

## Ethical Hacking Guidelines

✅ **DO:**
- Use on systems you own
- Get written permission before testing others' systems
- Use in educational environments
- Report vulnerabilities responsibly
- Help others learn ethically

❌ **DON'T:**
- Hack into systems without permission
- Use for malicious purposes
- Bypass security on systems you don't own
- Share exploits publicly
- Use in production systems without authorization

---

## Learning Resources

- **TryHackMe**: https://tryhackme.com/
- **HackTheBox**: https://www.hackthebox.com/
- **OWASP**: https://owasp.org/
- **PortSwigger Web Security Academy**: https://portswigger.net/web-security

---

## Troubleshooting

### "Permission Denied" on Packet Sniffer
Run with administrator/root privileges:
```bash
# Windows
py -3 -m pip install --user scapy
# Then run with admin cmd/PowerShell

# Linux/macOS
sudo python3 packet_analysis/packet_sniffer.py
```

### Import Errors
Ensure all dependencies are installed:
```bash
pip install requests bs4 scapy paramiko
```

### Scapy Not Working on Windows
Use Npcap instead of Winpcap:
```bash
# Install from: https://nmap.org/npcap/
# Then reinstall scapy:
pip install --upgrade scapy
```

---

## License

Educational use only. All tools provided as-is for learning purposes.

---

## Support & Questions

Refer to individual tool documentation or run with `--help` flag:
```bash
python hacking_tools/network_tools/port_scanner.py --help
```

---

**Stay ethical. Stay legal. Keep learning.** 🔐

