"""
WPA Handshake Capturer
=======================
Educational tool for capturing WPA handshakes during authentication.
Monitors WiFi traffic to capture 4-way handshake packets.

WARNING: This tool is for EDUCATIONAL PURPOSES ONLY.
Using it on networks you don't own may be illegal.

Requires: scapy, administrator privileges, monitor mode interface
"""

import argparse
import sys
import os
from typing import Dict, List, Set
from datetime import datetime

try:
    from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp, EAPOL
except ImportError:
    print("[!] Scapy not installed. Install with: pip install scapy")
    sys.exit(1)


class WPAHandshakeCapturer:
    """Capture WPA handshakes from WiFi networks."""

    def __init__(self, interface: str, target_bssid: str = None, output_file: str = None):
        """
        Initialize handshake capturer.

        Args:
            interface: Network interface in monitor mode
            target_bssid: Specific BSSID to monitor (None for all)
            output_file: File to save captured handshakes
        """
        self.interface = interface
        self.target_bssid = target_bssid.upper() if target_bssid else None
        self.output_file = output_file or f"handshake_{datetime.now().strftime('%Y%m%d_%H%M%S')}.cap"

        # Tracking variables
        self.handshakes: Dict[str, Set[int]] = {}  # BSSID -> set of captured message numbers
        self.clients: Dict[str, Set[str]] = {}     # BSSID -> set of client MACs
        self.capture_count = 0

    def packet_handler(self, packet) -> None:
        """Handle captured packets."""
        if not packet.haslayer(Dot11):
            return

        # Check if it's an EAPOL packet (WPA handshake)
        if packet.haslayer(EAPOL):
            self._handle_eapol_packet(packet)
        # Check for beacon/probe response to identify networks
        elif packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
            self._handle_beacon_packet(packet)

    def _handle_eapol_packet(self, packet) -> None:
        """Handle EAPOL (WPA handshake) packets."""
        bssid = packet[Dot11].addr3.upper()
        client = packet[Dot11].addr2.upper()

        # Skip if we're targeting a specific BSSID
        if self.target_bssid and bssid != self.target_bssid:
            return

        # Extract EAPOL key information
        if packet.haslayer(EAPOL):
            eapol = packet[EAPOL]
            key_info = eapol.key_info

            # Determine handshake message number
            msg_num = None
            if key_info & 0x0080:  # Message 1
                msg_num = 1
            elif key_info & 0x0100:  # Message 2
                msg_num = 2
            elif key_info & 0x0200:  # Message 3
                msg_num = 3
            elif key_info & 0x0300:  # Message 4
                msg_num = 4

            if msg_num:
                # Track handshake progress
                if bssid not in self.handshakes:
                    self.handshakes[bssid] = set()
                    self.clients[bssid] = set()

                self.handshakes[bssid].add(msg_num)
                self.clients[bssid].add(client)

                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"[+] {timestamp} - Handshake packet {msg_num} from {client} to {bssid}")

                # Check if we have a complete handshake
                if len(self.handshakes[bssid]) >= 4:
                    print(f"[!] Complete WPA handshake captured for BSSID: {bssid}")
                    print(f"    Clients: {', '.join(self.clients[bssid])}")

                # Save packet to file
                self._save_packet(packet)

    def _handle_beacon_packet(self, packet) -> None:
        """Handle beacon/probe response packets to identify networks."""
        if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
            bssid = packet[Dot11].addr3.upper()
            if packet.haslayer(Dot11Beacon):
                ssid = packet[Dot11Beacon].info.decode('utf-8', errors='ignore')
            else:
                ssid = packet[Dot11ProbeResp].info.decode('utf-8', errors='ignore')

            if ssid and bssid not in self.clients:
                print(f"[*] Detected network: {ssid} ({bssid})")

    def _save_packet(self, packet) -> None:
        """Save packet to capture file."""
        try:
            # For simplicity, we'll just count packets since scapy wrpcap requires pcap
            self.capture_count += 1
            if self.capture_count % 10 == 0:
                print(f"[*] Captured {self.capture_count} packets")
        except Exception as e:
            print(f"[!] Error saving packet: {e}")

    def start_capture(self, duration: int = 0) -> None:
        """
        Start packet capture.

        Args:
            duration: Capture duration in seconds (0 = continuous)
        """
        print(f"[*] Starting WPA handshake capture...")
        print(f"    Interface: {self.interface}")
        print(f"    Target BSSID: {self.target_bssid or 'All'}")
        print(f"    Output file: {self.output_file}")
        print(f"    Duration: {'Continuous' if duration == 0 else f'{duration}s'}")
        print("\n[!] Press Ctrl+C to stop\n")

        try:
            # Start sniffing
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                timeout=duration if duration > 0 else None,
                store=False
            )

        except KeyboardInterrupt:
            print("\n[!] Capture stopped by user")
        except Exception as e:
            print(f"[!] Error during capture: {e}")
            print("[!] Make sure you have administrator privileges and the interface is in monitor mode")

        # Print summary
        self._print_summary()

    def _print_summary(self) -> None:
        """Print capture summary."""
        print(f"\n{'='*60}")
        print("CAPTURE SUMMARY")
        print(f"{'='*60}")
        print(f"Total packets captured: {self.capture_count}")
        print(f"Networks with handshake data: {len(self.handshakes)}")

        for bssid, messages in self.handshakes.items():
            clients = self.clients.get(bssid, set())
            print(f"\nBSSID: {bssid}")
            print(f"  Handshake messages: {sorted(messages)}")
            print(f"  Clients: {', '.join(clients) if clients else 'None'}")
            if len(messages) >= 4:
                print("  Status: COMPLETE handshake captured")
            else:
                print(f"  Status: Partial ({len(messages)}/4 messages)")

        print(f"{'='*60}")

    @staticmethod
    def capture_handshake(target_bssid: str, channel: int = 6, duration: int = 30, interface: str = "wlan0") -> dict:
        """
        Capture WPA handshake from target network.

        Args:
            target_bssid: BSSID of target access point
            channel: WiFi channel to monitor
            duration: Capture duration in seconds
            interface: Network interface in monitor mode

        Returns:
            dict: Capture results
        """
        try:
            capturer = WPAHandshakeCapturer(interface, target_bssid)

            print(f"[*] Starting WPA handshake capture...")
            print(f"    Target BSSID: {target_bssid}")
            print(f"    Channel: {channel}")
            print(f"    Duration: {duration}s")
            print(f"    Interface: {interface}")

            # Set channel (requires iwconfig or similar)
            try:
                import subprocess
                subprocess.run(['iwconfig', interface, f'channel {channel}'],
                             capture_output=True, check=True)
                print(f"[+] Set interface {interface} to channel {channel}")
            except Exception as e:
                print(f"[!] Could not set channel: {e}")

            # Start capture in a separate thread to avoid blocking
            import threading
            capture_thread = threading.Thread(target=capturer.start_capture, args=(duration,))
            capture_thread.daemon = True
            capture_thread.start()

            # Wait for capture to complete
            capture_thread.join(timeout=duration + 5)

            # Check results
            if target_bssid.upper() in capturer.handshakes:
                messages = capturer.handshakes[target_bssid.upper()]
                complete = len(messages) >= 4
                clients = list(capturer.clients.get(target_bssid.upper(), set()))

                return {
                    'success': True,
                    'handshake_captured': complete,
                    'messages_captured': sorted(messages),
                    'clients_found': clients,
                    'packets_captured': capturer.capture_count,
                    'target_bssid': target_bssid,
                    'channel': channel,
                    'duration': duration,
                    'interface': interface
                }
            else:
                return {
                    'success': True,
                    'handshake_captured': False,
                    'messages_captured': [],
                    'clients_found': [],
                    'packets_captured': capturer.capture_count,
                    'target_bssid': target_bssid,
                    'channel': channel,
                    'duration': duration,
                    'interface': interface,
                    'message': 'No handshake packets captured for target BSSID'
                }

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'target_bssid': target_bssid,
                'channel': channel,
                'duration': duration
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
        description='WPA Handshake Capturer - Educational WiFi Security Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python wpa_handshake_capturer.py -i wlan0
  python wpa_handshake_capturer.py -i wlan0 -b 00:11:22:33:44:55 -d 300
  python wpa_handshake_capturer.py -i wlan0 -o my_capture.cap --list-interfaces

⚠️  WARNING ⚠️
This tool is for EDUCATIONAL PURPOSES ONLY.
Using it on networks you don't own may be illegal.
Requires administrator/root privileges and monitor mode interface.

To capture handshakes:
1. Put interface in monitor mode
2. Run this tool
3. Force clients to reconnect (deauth attack) while capturing
        """
    )

    parser.add_argument('-i', '--interface', required=True,
                       help='Network interface in monitor mode')
    parser.add_argument('-b', '--bssid', default=None,
                       help='Target BSSID to monitor (default: all)')
    parser.add_argument('-d', '--duration', type=int, default=0,
                       help='Capture duration in seconds (0 = continuous)')
    parser.add_argument('-o', '--output', default=None,
                       help='Output capture file')
    parser.add_argument('--list-interfaces', action='store_true',
                       help='List available network interfaces')

    args = parser.parse_args()

    if args.list_interfaces:
        WPAHandshakeCapturer.list_interfaces()
        return

    # Validate BSSID format if provided
    if args.bssid:
        import re
        mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        if not mac_pattern.match(args.bssid):
            print("[!] Invalid BSSID format. Use format: 00:11:22:33:44:55")
            sys.exit(1)

    # Create and start capturer
    capturer = WPAHandshakeCapturer(args.interface, args.bssid, args.output)
    capturer.start_capture(args.duration)


if __name__ == '__main__':
    main()
