"""
START HERE - Hacking Tools Suite Getting Started
=================================================
This file shows you everything you need to know to get started.
"""

WELCOME_MESSAGE = """
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║          🔐 HACKING TOOLS SUITE - EDUCATIONAL TOOLS 🔐         ║
║                                                                ║
║                    ⭐ START HERE ⭐                            ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝


🎯 WHAT YOU HAVE
════════════════

You now have a complete educational hacking toolkit with 7 powerful
security tools for learning cybersecurity concepts:

1. 🌐 PORT SCANNER          - Find open ports on any host
2. 🗺️  NETWORK MAPPER        - Discover active hosts on networks
3. 🔐 CIPHER TOOLS          - Encryption, decryption, hashing
4. 🎯 INJECTION TESTER      - SQL Injection & XSS detection
5. 🔑 PASSWORD ANALYZER     - Strength analysis & hash cracking
6. 📦 PACKET SNIFFER        - Capture & analyze network packets
7. ⚠️  PHISHING DETECTOR     - Detect social engineering attacks


✅ WHAT'S INCLUDED
═══════════════════

File/Folder              Purpose
─────────────────────────────────────────────────────────────
INDEX.py                Complete reference guide
QUICKSTART.py           Interactive quick start
SETUP.py                Installation instructions
README.md               Full documentation
requirements.txt        Python dependencies

hacking_tools/
├── launcher.py         Interactive tool launcher
├── network_tools/      Port scanning & network discovery
├── cryptography_tools/ Encryption & hashing utilities
├── web_security/       Vulnerability testing
├── password_tools/     Password analysis
├── packet_analysis/    Packet capture & analysis
└── social_engineering/ Phishing detection


🚀 GETTING STARTED IN 3 STEPS
═════════════════════════════

STEP 1: INSTALL DEPENDENCIES
─────────────────────────────
Open PowerShell in this folder and run:

    pip install -r requirements.txt

This installs:
  ✓ requests      (HTTP library)
  ✓ beautifulsoup4 (Web scraping)
  ✓ scapy         (Packet manipulation)
  ✓ paramiko      (SSH/SFTP)


STEP 2: VERIFY INSTALLATION
────────────────────────────
Check everything is working:

    python -c "import scapy, requests, bs4; print('✓ All set!')"


STEP 3: LAUNCH THE TOOLS
────────────────────────
Run the interactive launcher:

    python hacking_tools/launcher.py

Or run individual tools:

    python hacking_tools/network_tools/port_scanner.py localhost
    python hacking_tools/cryptography_tools/cipher_tools.py
    python hacking_tools/web_security/injection_tester.py


💡 QUICK EXAMPLES
═════════════════

EXAMPLE 1: Scan Your Computer for Open Ports
──────────────────────────────────────────────
python hacking_tools/network_tools/port_scanner.py localhost --ports 1-1000

Expected output:
[+] Port   80: OPEN (HTTP)
[+] Port  443: OPEN (HTTPS)
[*] Scan completed in 15.23 seconds
[*] Found 2 open port(s)


EXAMPLE 2: Encrypt a Message Using Caesar Cipher
──────────────────────────────────────────────────
python hacking_tools/cryptography_tools/cipher_tools.py

You'll see:
[*] Caesar Cipher:
    Original: HELLO WORLD
    Encrypted (shift=3): KHOOR ZRUOG
    Decrypted: HELLO WORLD


EXAMPLE 3: Test for SQL Injection Vulnerabilities
──────────────────────────────────────────────────
python hacking_tools/web_security/injection_tester.py

Shows how to detect and prevent:
✓ SQL Injection patterns
✓ XSS attack vectors
✓ Input sanitization methods


EXAMPLE 4: Analyze Password Strength
──────────────────────────────────────
python hacking_tools/password_tools/password_analyzer.py

Evaluates:
✓ Password length
✓ Character diversity
✓ Entropy calculation
✓ Strength score


EXAMPLE 5: Detect Phishing Emails
──────────────────────────────────
python hacking_tools/social_engineering/phishing_detector.py

Identifies:
✓ Suspicious domains
✓ Phishing keywords
✓ Malicious links
✓ Red flags & warnings


📖 DOCUMENTATION
════════════════

For detailed information, check:

README.md      - Full tool documentation with examples
QUICKSTART.py  - Interactive quick start guide
SETUP.py       - Installation & troubleshooting
INDEX.py       - Complete reference manual


🎓 LEARNING RESOURCES
═════════════════════

Online Platforms (FREE):
  • TryHackMe: https://tryhackme.com/
  • HackTheBox: https://www.hackthebox.com/
  • OWASP WebGoat: https://owasp.org/WebGoat/

Topics to Learn:
  ✓ Network scanning & reconnaissance
  ✓ Cryptography & encryption
  ✓ Web vulnerabilities
  ✓ Password security
  ✓ Packet analysis
  ✓ Social engineering


⚡ PRO TIPS
════════════

1. Use --help Flag
   python hacking_tools/network_tools/port_scanner.py --help

2. Combine Tools
   # Scan for hosts, then scan their ports
   python hacking_tools/network_tools/network_mapper.py 192.168.1.0/24
   python hacking_tools/network_tools/port_scanner.py 192.168.1.100

3. Read Source Code
   Open each tool's .py file to understand the implementation

4. Modify Tools
   Try adding features or combining multiple tools

5. Run in Admin PowerShell
   For packet sniffer, run PowerShell as Administrator


⚠️  IMPORTANT - READ THIS!
═══════════════════════════

🔒 LEGAL REQUIREMENTS:

✓ ONLY use these tools on:
  • Systems YOU OWN
  • Systems with EXPLICIT WRITTEN PERMISSION
  • Authorized educational/test environments

✗ DO NOT use for:
  • Hacking systems you don't own
  • Causing damage or disruption
  • Illegal activities
  • Bypassing security without authorization

⚖️  UNAUTHORIZED ACCESS IS ILLEGAL
   Breaking the law has serious consequences!


🔐 ETHICAL HACKING PRINCIPLES
══════════════════════════════

✓ Respect Privacy
✓ Get Authorization First
✓ Only Test What You Agreed To
✓ Report Findings Responsibly
✓ Don't Cause Harm
✓ Follow All Laws


🆘 TROUBLESHOOTING
═══════════════════

Problem: Module not found
Solution: cd to the correct directory and check requirements installed

Problem: Port scanner can't connect
Solution: Target might be offline or firewall blocking connections

Problem: Packet sniffer permission denied
Solution: Run PowerShell as Administrator

Problem: Can't install scapy
Solution: See SETUP.py for detailed Windows/Linux/macOS instructions


❓ FREQUENTLY ASKED QUESTIONS
═════════════════════════════

Q: Is it legal to use these tools?
A: They're legal for learning. Only use on authorized systems.

Q: Do I need to be a hacker?
A: No! These are educational. You'll learn while using them.

Q: Can I modify the tools?
A: Yes! Read the source code and customize for your needs.

Q: Will this help me get a security job?
A: Yes! Understanding these concepts is valuable for cyber careers.

Q: What if I get stuck?
A: Check README.md, SETUP.py, or read the tool source code.


🎯 YOUR LEARNING PATH
═════════════════════

Beginner (Start Here):
  1. Run QUICKSTART.py to see overview
  2. Try Cipher Tools - understand encryption
  3. Try Injection Tester - learn vulnerabilities
  4. Try Password Analyzer - understand security

Intermediate:
  1. Try Port Scanner - scan localhost
  2. Try Network Mapper - discover your network
  3. Try Phishing Detector - learn threats
  4. Read tool source code

Advanced:
  1. Modify tools for new scenarios
  2. Combine tools for complex tasks
  3. Deploy on test networks
  4. Add new features


🚀 NEXT STEPS
═════════════

1. Run the launcher:
   python hacking_tools/launcher.py

2. Try each tool with the examples

3. Read the source code to understand how it works

4. Modify tools to add your own features

5. Practice on TryHackMe or HackTheBox

6. Join a cybersecurity community

7. Keep learning and stay ethical!


📞 SUPPORT
══════════

Tool Help:              Use --help flag
General Questions:      Read README.md
Setup Issues:          Check SETUP.py
Reference Guide:       See INDEX.py
Examples:              Check QUICKSTART.py


╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║                   🎉 YOU'RE READY TO START! 🎉                ║
║                                                                ║
║   Run: python hacking_tools/launcher.py                       ║
║                                                                ║
║       Stay Ethical | Stay Legal | Keep Learning              ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
"""

print(WELCOME_MESSAGE)

if __name__ == '__main__':
    print("\n" + "="*60)
    print("What would you like to do?")
    print("="*60)
    print("1. View this message again:    python START_HERE.py")
    print("2. Run the launcher:           python hacking_tools/launcher.py")
    print("3. View quick examples:        python QUICKSTART.py")
    print("4. View full documentation:    python README.md")
    print("5. View installation help:     python SETUP.py")
    print("="*60)
    print("\nStart by running: python hacking_tools/launcher.py")
    print("="*60)
