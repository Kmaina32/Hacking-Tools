"""
Packet Sniffer - Network Packet Analysis Tool
==============================================
Educational tool for capturing and analyzing network packets.

NOTE: Requires administrator/root privileges and scapy library.
USAGE: python packet_sniffer.py [--interface INTERFACE] [--count COUNT] [--filter FILTER]

Examples:
  python packet_sniffer.py --count 10
  python packet_sniffer.py --interface eth0 --filter "tcp port 80"
  python packet_sniffer.py --filter "ip src 192.168.1.1"
"""

import argparse
import sys
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw
except ImportError:
    print("[!] Scapy not installed. Install with: pip install scapy")
    sys.exit(1)


class PacketAnalyzer:
    """Analyze network packets."""
    
    def __init__(self, interface=None, packet_count=0, packet_filter=None):
        """Initialize packet analyzer."""
        self.interface = interface
        self.packet_count = packet_count
        self.packet_filter = packet_filter
        self.packets_captured = 0
        self.stats = {
            'total': 0,
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'dns': 0,
            'other': 0,
        }
    
    def packet_callback(self, packet):
        """Callback function for each captured packet."""
        self.packets_captured += 1
        self.stats['total'] += 1
        
        # Build packet info
        packet_info = {
            'timestamp': datetime.now().strftime("%H:%M:%S"),
            'number': self.packets_captured,
            'length': len(packet),
        }
        
        # Extract IP layer
        if IP in packet:
            ip_layer = packet[IP]
            packet_info['src_ip'] = ip_layer.src
            packet_info['dst_ip'] = ip_layer.dst
            packet_info['ttl'] = ip_layer.ttl
            packet_info['protocol'] = ip_layer.proto
            
            # Determine protocol and extract details
            if TCP in packet:
                self.stats['tcp'] += 1
                tcp_layer = packet[TCP]
                packet_info['protocol_name'] = 'TCP'
                packet_info['src_port'] = tcp_layer.sport
                packet_info['dst_port'] = tcp_layer.dport
                packet_info['flags'] = str(tcp_layer.flags)
                self._print_tcp_packet(packet_info, packet)
            
            elif UDP in packet:
                self.stats['udp'] += 1
                udp_layer = packet[UDP]
                packet_info['protocol_name'] = 'UDP'
                packet_info['src_port'] = udp_layer.sport
                packet_info['dst_port'] = udp_layer.dport
                
                # Check for DNS
                if DNS in packet:
                    self.stats['dns'] += 1
                    packet_info['protocol_name'] = 'DNS'
                    self._print_dns_packet(packet_info, packet)
                else:
                    self._print_udp_packet(packet_info, packet)
            
            elif ICMP in packet:
                self.stats['icmp'] += 1
                packet_info['protocol_name'] = 'ICMP'
                self._print_icmp_packet(packet_info, packet)
            
            else:
                self.stats['other'] += 1
                self._print_ip_packet(packet_info)
        
        else:
            self.stats['other'] += 1
            print(f"[*] Packet #{self.packets_captured}: Non-IP packet ({len(packet)} bytes)")
    
    def _print_tcp_packet(self, info, packet):
        """Print TCP packet details."""
        print(f"\n[+] TCP Packet #{info['number']} [{info['timestamp']}]")
        print(f"    Source: {info['src_ip']}:{info['src_port']}")
        print(f"    Destination: {info['dst_ip']}:{info['dst_port']}")
        print(f"    Flags: {info['flags']}")
        print(f"    Length: {info['length']} bytes")
        
        # Print payload if exists
        if Raw in packet:
            payload = packet[Raw].load
            if len(payload) > 0:
                print(f"    Payload (first 50 bytes): {str(payload[:50])}")
    
    def _print_udp_packet(self, info, packet):
        """Print UDP packet details."""
        print(f"\n[+] UDP Packet #{info['number']} [{info['timestamp']}]")
        print(f"    Source: {info['src_ip']}:{info['src_port']}")
        print(f"    Destination: {info['dst_ip']}:{info['dst_port']}")
        print(f"    Length: {info['length']} bytes")
    
    def _print_dns_packet(self, info, packet):
        """Print DNS packet details."""
        dns_layer = packet[DNS]
        print(f"\n[+] DNS Packet #{info['number']} [{info['timestamp']}]")
        print(f"    Source: {info['src_ip']}:{info['src_port']}")
        print(f"    Destination: {info['dst_ip']}:{info['dst_port']}")
        
        if DNSQR in packet:
            dns_query = packet[DNSQR]
            print(f"    Query: {dns_query.qname.decode()}")
    
    def _print_icmp_packet(self, info, packet):
        """Print ICMP packet details."""
        icmp_layer = packet[ICMP]
        print(f"\n[+] ICMP Packet #{info['number']} [{info['timestamp']}]")
        print(f"    Source: {info['src_ip']}")
        print(f"    Destination: {info['dst_ip']}")
        print(f"    Type: {icmp_layer.type}")
        print(f"    Code: {icmp_layer.code}")
    
    def _print_ip_packet(self, info):
        """Print generic IP packet details."""
        print(f"\n[*] IP Packet #{info['number']} [{info['timestamp']}]")
        print(f"    Source: {info['src_ip']}")
        print(f"    Destination: {info['dst_ip']}")
        print(f"    Protocol: {info['protocol']}")
        print(f"    Length: {info['length']} bytes")
    
    def start_sniffing(self):
        """Start packet capture."""
        print("\n[*] Starting packet sniffer...")
        print("[!] Press Ctrl+C to stop\n")
        
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                count=self.packet_count if self.packet_count > 0 else 0,
                filter=self.packet_filter,
                store=False,
            )
        except PermissionError:
            print("[!] Error: This tool requires administrator/root privileges")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Error: {e}")
            sys.exit(1)
        finally:
            self.print_statistics()
    
    def print_statistics(self):
        """Print capture statistics."""
        print("\n" + "="*50)
        print("PACKET CAPTURE STATISTICS")
        print("="*50)
        print(f"Total Packets: {self.stats['total']}")
        print(f"  TCP: {self.stats['tcp']}")
        print(f"  UDP: {self.stats['udp']}")
        print(f"  DNS: {self.stats['dns']}")
        print(f"  ICMP: {self.stats['icmp']}")
        print(f"  Other: {self.stats['other']}")
        print("="*50)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Packet Sniffer - Capture and analyze network packets',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python packet_sniffer.py --count 10
  python packet_sniffer.py --interface eth0 --filter "tcp port 80"
  python packet_sniffer.py --filter "ip src 192.168.1.1"

Note: Requires administrator/root privileges
        """
    )
    
    parser.add_argument('--interface', '-i', help='Network interface to sniff on')
    parser.add_argument('--count', '-c', type=int, default=0,
                       help='Number of packets to capture (0 = unlimited)')
    parser.add_argument('--filter', '-f', help='BPF filter (e.g., "tcp port 80")')
    
    args = parser.parse_args()
    
    analyzer = PacketAnalyzer(args.interface, args.count, args.filter)
    
    try:
        analyzer.start_sniffing()
    except KeyboardInterrupt:
        print("\n[!] Packet capture interrupted by user")
        analyzer.print_statistics()


if __name__ == '__main__':
    main()
