#!/usr/bin/env python3
"""
Setup and Requirements File
============================
Lists all dependencies and setup instructions.
"""

REQUIREMENTS = {
    'required': [
        'requests>=2.28.0',      # HTTP library for web requests
        'beautifulsoup4>=4.11.0', # Web scraping
        'scapy>=2.5.0',          # Packet manipulation
        'paramiko>=3.0.0',       # SSH/SFTP library
    ],
    'optional': [
        'colorama>=0.4.0',       # Colored terminal output
        'tabulate>=0.9.0',       # Pretty tables
        'tqdm>=4.64.0',          # Progress bars
    ]
}

INSTALLATION_STEPS = """
INSTALLATION STEPS
==================

1. WINDOWS SETUP
   ─────────────
   
   a) Install Python 3.7+ from https://www.python.org/
   b) Open PowerShell as Administrator
   c) Navigate to the project directory:
      cd "C:\\Users\\Engineer Kairo Maina\\Desktop\\Hacking Tools"
   
   d) Create virtual environment (recommended):
      python -m venv venv
      .\\venv\\Scripts\\Activate.ps1
   
   e) Install requirements:
      pip install -r requirements.txt


2. LINUX/macOS SETUP
   ─────────────────
   
   a) Ensure Python 3.7+ is installed:
      python3 --version
   
   b) Create virtual environment:
      python3 -m venv venv
      source venv/bin/activate
   
   c) Install requirements:
      pip install -r requirements.txt
   
   d) For packet sniffer, install libpcap:
      
      Ubuntu/Debian:
      sudo apt-get install libpcap-dev
      
      macOS:
      brew install libpcap


3. VERIFY INSTALLATION
   ──────────────────
   
   python -c "import scapy, requests, bs4, paramiko; print('✓ All packages installed')"


4. SPECIFIC TOOL REQUIREMENTS
   ─────────────────────────
   
   Port Scanner:
   - No additional requirements
   
   Network Mapper:
   - Windows: Built-in (uses ping)
   - Linux/macOS: Built-in (uses ping)
   
   Cryptography Tools:
   - No additional requirements (uses built-in hashlib)
   
   Injection Tester:
   - No additional requirements
   
   Password Analyzer:
   - No additional requirements
   
   Packet Sniffer:
   - REQUIRES: Administrator/root privileges
   - REQUIRES: scapy library
   - REQUIRES: libpcap (Linux/macOS) or Npcap (Windows)
   
   Phishing Detector:
   - No additional requirements


5. PACKET SNIFFER SETUP (SPECIAL)
   ──────────────────────────────
   
   WINDOWS:
   --------
   a) Download and install Npcap from:
      https://nmap.org/npcap/
   
   b) Run PowerShell as Administrator
   
   c) Install/upgrade scapy:
      pip install --upgrade scapy
   
   d) Run packet sniffer as Administrator
   
   
   LINUX:
   ------
   a) Install libpcap:
      sudo apt-get install libpcap-dev
   
   b) Install scapy:
      pip install scapy
   
   c) Run packet sniffer with sudo:
      sudo python3 hacking_tools/packet_analysis/packet_sniffer.py
   
   
   macOS:
   ------
   a) Install libpcap:
      brew install libpcap
   
   b) Install scapy:
      pip install scapy
   
   c) Run packet sniffer with sudo:
      sudo python3 hacking_tools/packet_analysis/packet_sniffer.py


TROUBLESHOOTING
===============

If you encounter issues:

1. Update pip:
   python -m pip install --upgrade pip

2. Clear pip cache:
   pip cache purge

3. Reinstall packages:
   pip uninstall scapy requests bs4 paramiko -y
   pip install scapy requests bs4 paramiko

4. Check Python version:
   python --version
   # Should be 3.7 or higher

5. Virtual environment issues:
   # Remove venv and recreate:
   rm -r venv  # or del venv on Windows
   python -m venv venv
   source venv/bin/activate  # or .\\venv\\Scripts\\Activate.ps1


OPTIONAL ENHANCEMENTS
====================

For better user experience, optionally install:

pip install colorama tabulate tqdm

These add:
- Colored output
- Pretty tables
- Progress bars


GETTING STARTED
===============

Once installed, run:

   python hacking_tools/launcher.py

Or read QUICKSTART.py for examples.
"""

print(INSTALLATION_STEPS)

if __name__ == '__main__':
    print("\n" + "="*60)
    print("REQUIREMENTS SUMMARY")
    print("="*60)
    
    print("\nRequired packages:")
    for pkg in REQUIREMENTS['required']:
        print(f"  • {pkg}")
    
    print("\nOptional packages:")
    for pkg in REQUIREMENTS['optional']:
        print(f"  • {pkg}")
    
    print("\n" + "="*60)
    print("Install with: pip install -r requirements.txt")
    print("="*60)
