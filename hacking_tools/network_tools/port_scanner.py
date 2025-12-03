"""
Port Scanner - Network Reconnaissance Tool
===========================================
Scans target hosts for open ports using socket connections.
Educational tool for understanding network services.

USAGE: python port_scanner.py <target> [--ports PORT_RANGE] [--timeout TIMEOUT]
"""

import socket
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import time


class PortScanner:
    """Scan ports on a target host."""
    
    # Common ports and their services
    COMMON_PORTS = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 465: 'SMTPS',
        587: 'SMTP TLS', 993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL',
        3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP Proxy',
        8443: 'HTTPS Alt', 27017: 'MongoDB', 6379: 'Redis'
    }
    
    def __init__(self, target, timeout=1):
        """Initialize scanner with target and timeout."""
        self.target = target
        self.timeout = timeout
        self.open_ports = []
    
    def resolve_host(self):
        """Resolve hostname to IP address."""
        try:
            ip = socket.gethostbyname(self.target)
            print(f"[*] Resolved {self.target} to {ip}")
            return ip
        except socket.gaierror:
            print(f"[!] Could not resolve hostname: {self.target}")
            return None
    
    def scan_port(self, port):
        """Scan a single port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                service = self.COMMON_PORTS.get(port, 'Unknown')
                self.open_ports.append((port, service))
                print(f"[+] Port {port:5d}: OPEN ({service})")
                return True
            return False
        except socket.error as e:
            print(f"[!] Error scanning port {port}: {e}")
            return False
    
    def scan_range(self, start_port, end_port, threads=50):
        """Scan a range of ports using multithreading."""
        print(f"\n[*] Starting scan on {self.target} from port {start_port} to {end_port}")
        print(f"[*] Using {threads} threads, timeout: {self.timeout}s\n")
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self.scan_port, port): port 
                      for port in range(start_port, end_port + 1)}
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"[!] Thread error: {e}")
        
        elapsed = time.time() - start_time
        
        print(f"\n[*] Scan completed in {elapsed:.2f} seconds")
        print(f"[*] Found {len(self.open_ports)} open port(s)")
        
        if self.open_ports:
            print("\n[*] Open Ports Summary:")
            for port, service in sorted(self.open_ports):
                print(f"    {port:5d} - {service}")


def parse_port_range(port_string):
    """Parse port range string (e.g., '1-1000' or '80,443,8080')."""
    if '-' in port_string:
        start, end = port_string.split('-')
        return int(start), int(end)
    elif ',' in port_string:
        ports = [int(p) for p in port_string.split(',')]
        return ports[0], ports[-1]
    else:
        port = int(port_string)
        return port, port


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Port Scanner - Scan target for open ports',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python port_scanner.py 192.168.1.1 --ports 1-1000
  python port_scanner.py example.com --ports 80,443,8080
  python port_scanner.py localhost --ports 1-65535 --timeout 2
        """
    )
    
    parser.add_argument('target', help='Target host (IP or hostname)')
    parser.add_argument('--ports', default='1-1000', 
                       help='Port range to scan (default: 1-1000)')
    parser.add_argument('--timeout', type=float, default=1,
                       help='Socket timeout in seconds (default: 1)')
    parser.add_argument('--threads', type=int, default=50,
                       help='Number of threads (default: 50)')
    
    args = parser.parse_args()
    
    try:
        start_port, end_port = parse_port_range(args.ports)
        if start_port < 1 or end_port > 65535:
            print("[!] Port range must be between 1 and 65535")
            sys.exit(1)
        
        scanner = PortScanner(args.target, args.timeout)
        if scanner.resolve_host():
            scanner.scan_range(start_port, end_port, args.threads)
    
    except ValueError:
        print("[!] Invalid port format. Use '1-1000' or '80,443,8080'")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(0)


if __name__ == '__main__':
    main()
