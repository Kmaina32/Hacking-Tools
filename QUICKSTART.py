"""
Quick Start Guide - Getting Started with Hacking Tools
=======================================================
"""

print("""
╔════════════════════════════════════════════════════════════════╗
║           HACKING TOOLS SUITE - QUICK START GUIDE              ║
╚════════════════════════════════════════════════════════════════╝

STEP 1: INSTALLATION
====================

1. Open PowerShell in the workspace folder
2. Install required packages:
   
   pip install requests bs4 scapy paramiko

3. Verify installation:
   
   python -c "import scapy, requests, bs4, paramiko; print('✓ All packages installed')"


STEP 2: RUN THE LAUNCHER
========================

Start the interactive menu:

   python hacking_tools/launcher.py

Or run individual tools:

   python hacking_tools/network_tools/port_scanner.py --help
   python hacking_tools/cryptography_tools/cipher_tools.py
   python hacking_tools/web_security/injection_tester.py


STEP 3: COMMON TASKS
====================

PORT SCANNING
─────────────
Scan your localhost for open ports:

   python hacking_tools/network_tools/port_scanner.py localhost --ports 1-10000

Scan a specific network (requires proper permissions):

   python hacking_tools/network_tools/port_scanner.py 192.168.1.1 --ports 80,443,3306,5432


NETWORK DISCOVERY
─────────────────
Find active hosts on your network:

   python hacking_tools/network_tools/network_mapper.py 192.168.1.0/24

   ⚠️  Note: This requires the target network to be accessible


ENCRYPTION/DECRYPTION
─────────────────────
Run interactive demo:

   python hacking_tools/cryptography_tools/cipher_tools.py

Use in Python code:

   from hacking_tools.cryptography_tools.cipher_tools import CaesarCipher
   
   plaintext = "HELLO WORLD"
   encrypted = CaesarCipher.encrypt(plaintext, 3)
   print(encrypted)  # KHOOR ZRUOG


TEST FOR VULNERABILITIES
─────────────────────────
Run SQL Injection and XSS testing:

   python hacking_tools/web_security/injection_tester.py


ANALYZE PASSWORDS
─────────────────
Check password strength:

   python hacking_tools/password_tools/password_analyzer.py

Example:
   from hacking_tools.password_tools.password_analyzer import PasswordStrengthAnalyzer
   
   analysis = PasswordStrengthAnalyzer.analyze("MyP@ssw0rd!")
   print(f"Strength: {analysis['strength']}")


PACKET SNIFFING
───────────────
⚠️  REQUIRES ADMIN/ROOT PRIVILEGES

Windows - Run PowerShell as Administrator:

   python hacking_tools/packet_analysis/packet_sniffer.py --count 10

Capture HTTP traffic:

   python hacking_tools/packet_analysis/packet_sniffer.py --filter "tcp port 80"


PHISHING DETECTION
──────────────────
Learn to identify phishing:

   python hacking_tools/social_engineering/phishing_detector.py


STEP 4: IMPORTANT REMINDERS
============================

✓ Legal Use Only
  - Only test systems you own or have explicit permission to test
  - Unauthorized access is illegal

✓ Ethical Hacking
  - Follow responsible disclosure practices
  - Report vulnerabilities to affected organizations
  - Don't cause harm or disruption

✓ Educational Purpose
  - These are learning tools
  - Understand the concepts, not just run the tools
  - Read the source code to learn


STEP 5: NEXT STEPS
==================

1. Read the README.md for detailed tool documentation

2. Explore the source code to understand:
   - How network scanning works
   - Cipher algorithms
   - Vulnerability detection
   - Password analysis

3. Try modifying the tools:
   - Add new cipher types
   - Extend port scanner features
   - Create custom detection rules

4. Practice on:
   - TryHackMe (https://tryhackme.com/)
   - HackTheBox (https://www.hackthebox.com/)
   - OWASP WebGoat

5. Join the Security Community:
   - Follow security researchers
   - Read security blogs
   - Participate in CTF competitions


TROUBLESHOOTING
===============

Problem: "ModuleNotFoundError: No module named 'scapy'"
Solution: pip install scapy

Problem: Permission Denied on packet sniffer
Solution: Run PowerShell as Administrator

Problem: Import errors when running tools
Solution: Verify you're in the correct directory and all packages are installed

Problem: "No such file or directory"
Solution: Use absolute paths or ensure you're in the correct working directory


SUPPORT
=======

For detailed information, see:
- README.md - Full documentation
- Individual tool --help flags
- Source code comments


Good luck learning ethical hacking! 🔐

""")
