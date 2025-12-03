"""
Main Launcher - Hacking Tools Suite
====================================
Launch and manage all security tools from one place.
"""

import os
import sys
import subprocess
from pathlib import Path


TOOLS_MENU = {
    '1': {
        'name': 'Port Scanner',
        'description': 'Scan target for open ports',
        'module': 'network_tools.port_scanner',
        'file': 'network_tools/port_scanner.py',
    },
    '2': {
        'name': 'Network Mapper',
        'description': 'Discover active hosts on a network',
        'module': 'network_tools.network_mapper',
        'file': 'network_tools/network_mapper.py',
    },
    '3': {
        'name': 'Cipher Tools',
        'description': 'Encryption/decryption and hash utilities',
        'module': 'cryptography_tools.cipher_tools',
        'file': 'cryptography_tools/cipher_tools.py',
    },
    '4': {
        'name': 'Injection Tester',
        'description': 'Test for SQL Injection and XSS vulnerabilities',
        'module': 'web_security.injection_tester',
        'file': 'web_security/injection_tester.py',
    },
    '5': {
        'name': 'Password Analyzer',
        'description': 'Analyze password strength and crack hashes',
        'module': 'password_tools.password_analyzer',
        'file': 'password_tools/password_analyzer.py',
    },
    '6': {
        'name': 'Packet Sniffer',
        'description': 'Capture and analyze network packets',
        'module': 'packet_analysis.packet_sniffer',
        'file': 'packet_analysis/packet_sniffer.py',
    },
    '7': {
        'name': 'Phishing Detector',
        'description': 'Detect phishing indicators and raise awareness',
        'module': 'social_engineering.phishing_detector',
        'file': 'social_engineering/phishing_detector.py',
    },
}


def print_banner():
    """Print application banner."""
    banner = """
╔════════════════════════════════════════════════════════════════╗
║                   HACKING TOOLS SUITE v1.0                     ║
║              Educational Security Tools for Learning            ║
╚════════════════════════════════════════════════════════════════╝

⚠️  DISCLAIMER ⚠️
These tools are for EDUCATIONAL PURPOSES ONLY. Only use them on:
  • Systems you own
  • Systems you have explicit written permission to test
  • Controlled educational environments

Unauthorized access to computer systems is ILLEGAL.

════════════════════════════════════════════════════════════════
    """
    print(banner)


def print_menu():
    """Print main menu."""
    print("\n" + "="*60)
    print("AVAILABLE TOOLS")
    print("="*60)
    
    for key, tool in sorted(TOOLS_MENU.items()):
        print(f"\n  [{key}] {tool['name']}")
        print(f"      {tool['description']}")
    
    print(f"\n  [0] Exit")
    print("\n" + "="*60)


def run_tool(tool_key, args=None):
    """Run selected tool."""
    if tool_key not in TOOLS_MENU:
        print("[!] Invalid selection")
        return
    
    tool = TOOLS_MENU[tool_key]
    
    print(f"\n[*] Starting {tool['name']}...")
    print("-" * 60)
    
    try:
        # Run as module
        module_name = tool['module']
        module = __import__(module_name, fromlist=['main'])
        
        if hasattr(module, 'main'):
            if args:
                sys.argv = ['python', *args]
            module.main()
        else:
            print(f"[!] Module {module_name} has no main() function")
    
    except ImportError as e:
        print(f"[!] Could not import module: {e}")
        print(f"[*] Try running as script instead:")
        print(f"    python {tool['file']} --help")
    except KeyboardInterrupt:
        print("\n[!] Tool interrupted by user")
    except SystemExit:
        pass  # Normal exit from tool
    except Exception as e:
        print(f"[!] Error running tool: {e}")


def main():
    """Main launcher."""
    print_banner()
    
    while True:
        print_menu()
        
        try:
            choice = input("\n[?] Select a tool (0-7): ").strip()
            
            if choice == '0':
                print("\n[*] Exiting Hacking Tools Suite. Stay safe and ethical!")
                break
            
            if choice in TOOLS_MENU:
                run_tool(choice)
                input("\n[*] Press Enter to continue...")
            else:
                print("[!] Invalid selection. Please try again.")
        
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
            break
        except Exception as e:
            print(f"[!] Error: {e}")


if __name__ == '__main__':
    main()
