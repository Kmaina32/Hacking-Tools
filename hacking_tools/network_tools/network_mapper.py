"""
Network Mapper - Network Discovery Tool
========================================
Discovers active hosts on a network using ping and ARP.
Educational tool for understanding network topology.

USAGE: python network_mapper.py <network_range>
Example: python network_mapper.py 192.168.1.0/24
"""

import socket
import subprocess
import sys
import platform
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress


class NetworkMapper:
    """Map active hosts on a network."""
    
    def __init__(self, network_range, timeout=2):
        """Initialize mapper with network range."""
        try:
            self.network = ipaddress.ip_network(network_range, strict=False)
            self.timeout = timeout
            self.active_hosts = []
        except ValueError as e:
            print(f"[!] Invalid network range: {e}")
            sys.exit(1)
    
    def ping_host(self, ip):
        """Ping a host to check if it's active."""
        try:
            # Different ping commands for Windows and Unix
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '1', '-w' if param == '-n' else '-W', 
                      str(int(self.timeout * 1000)), str(ip)]
            
            response = subprocess.run(command, capture_output=True, 
                                    timeout=self.timeout + 1)
            
            if response.returncode == 0:
                self.active_hosts.append(str(ip))
                print(f"[+] {ip} is ACTIVE")
                return True
            return False
        except subprocess.TimeoutExpired:
            return False
        except Exception as e:
            print(f"[!] Error pinging {ip}: {e}")
            return False
    
    def get_hostname(self, ip):
        """Resolve IP to hostname."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except (socket.herror, socket.error):
            return None
    
    def scan_network(self, threads=50):
        """Scan all hosts in the network."""
        hosts = list(self.network.hosts())
        total_hosts = len(hosts)
        
        print(f"\n[*] Scanning network: {self.network}")
        print(f"[*] Total hosts to scan: {total_hosts}")
        print(f"[*] Using {threads} threads, timeout: {self.timeout}s\n")
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self.ping_host, host): host 
                      for host in hosts}
            
            completed = 0
            for future in as_completed(futures):
                completed += 1
                try:
                    future.result()
                except Exception as e:
                    print(f"[!] Error: {e}")
                
                # Progress indicator
                if completed % 10 == 0:
                    print(f"[*] Progress: {completed}/{total_hosts} hosts scanned")
        
        return self.active_hosts
    
    def generate_report(self):
        """Generate scan report with resolved hostnames."""
        print(f"\n{'='*60}")
        print(f"NETWORK SCAN REPORT - {self.network}")
        print(f"{'='*60}")
        print(f"Active Hosts Found: {len(self.active_hosts)}\n")
        
        if self.active_hosts:
            print(f"{'IP Address':<20} {'Hostname':<30}")
            print(f"{'-'*50}")
            
            for ip in sorted(self.active_hosts, 
                           key=lambda x: ipaddress.ip_address(x)):
                hostname = self.get_hostname(ip)
                hostname = hostname or "N/A"
                print(f"{ip:<20} {hostname:<30}")
        else:
            print("[!] No active hosts found")
        
        print(f"{'='*60}\n")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Network Mapper - Discover active hosts on a network',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python network_mapper.py 192.168.1.0/24
  python network_mapper.py 10.0.0.0/24 --timeout 3
  python network_mapper.py 172.16.0.0/16 --threads 100
        """
    )
    
    parser.add_argument('network', help='Network range (CIDR notation, e.g., 192.168.1.0/24)')
    parser.add_argument('--timeout', type=float, default=2,
                       help='Ping timeout in seconds (default: 2)')
    parser.add_argument('--threads', type=int, default=50,
                       help='Number of threads (default: 50)')
    
    args = parser.parse_args()
    
    try:
        mapper = NetworkMapper(args.network, args.timeout)
        active_hosts = mapper.scan_network(args.threads)
        mapper.generate_report()
    
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(0)


if __name__ == '__main__':
    main()
