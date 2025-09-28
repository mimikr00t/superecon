#!/usr/bin/env python3
"""
🔥 SUPERECON - ULTIMATE RECON TOOL - All-in-One Reconnaissance Suite
Author: Security Researcher
Version: 2.0
Description: Comprehensive reconnaissance tool that combines multiple techniques
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
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class UltimateReconTool:
    def __init__(self, target, threads=100, timeout=5):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.results = {
            'target': target,
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
        
        # Common subdomains wordlist
        self.subdomain_wordlist = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 
            'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 
            'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 
            'web', 'media', 'email', 'api', 'cdn', 'storage', 'backup', 'db', 'database',
            'app', 'apps', 'cloud', 'server', 'servers', 'staging', 'prod', 'production',
            'test', 'testing', 'demo', 'stage', 'dev', 'development', 'secure', 'admin',
            'administrator', 'login', 'signin', 'dashboard', 'panel', 'control', 'cms',
            'wordpress', 'joomla', 'drupal', 'magento', 'shopify', 'aws', 's3', 'bucket'
        ]
        
        # Common ports for scanning
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 
            1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 
            8443, 9000, 9200, 27017, 28017
        ]

    def banner(self):
        print("""
╔════════════════════════════════════════════════════════════════╗
║              🔥 SEPERECON -ULTIMATE RECON TOOL                 ║
║                   All-in-One Reconnaissance                    ║
║                         Version 2.0                            ║
╚════════════════════════════════════════════════════════════════╝
        """)
        print(f"[*] Target: {self.target}")
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
                'emails': w.emails
            }
            print(f"    Registrar: {w.registrar}")
            print(f"    Creation Date: {w.creation_date}")
            print(f"    Expiration Date: {w.expiration_date}")
            print(f"    Name Servers: {w.name_servers}")
        except Exception as e:
            print(f"[-] WHOIS lookup failed: {e}")

    def dns_enumeration(self):
        """Enumerate all DNS records"""
        try:
            print(f"\n[+] Enumerating DNS records...")
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(self.target, record_type, raise_on_no_answer=False)
                    if answers.rrset:
                        records = [str(rdata) for rdata in answers]
                        self.results['dns_records'][record_type] = records
                        print(f"    {record_type}: {', '.join(records)}")
                except:
                    continue
                    
        except Exception as e:
            print(f"[-] DNS enumeration failed: {e}")

    def subdomain_enumeration(self):
        """Advanced subdomain enumeration using multiple techniques"""
        print(f"\n[+] Starting advanced subdomain enumeration...")
        
        found_subdomains = set()
        
        # Method 1: Certificate Transparency Logs
        print("    [1/4] Checking Certificate Transparency logs...")
        ct_subs = self.certificate_transparency_lookup()
        found_subdomains.update(ct_subs)
        
        # Method 2: DNS Bruteforce
        print("    [2/4] Performing DNS bruteforce...")
        dns_subs = self.dns_bruteforce()
        found_subdomains.update(dns_subs)
        
        # Method 3: Search Engine scraping
        print("    [3/4] Checking search engines...")
        search_subs = self.search_engine_enumeration()
        found_subdomains.update(search_subs)
        
        # Method 4: DNS zone transfer attempt
        print("    [4/4] Attempting DNS zone transfer...")
        zone_subs = self.dns_zone_transfer()
        found_subdomains.update(zone_subs)
        
        # Verify subdomains are live
        verified_subs = self.verify_subdomains(found_subdomains)
        
        self.results['subdomains'] = list(verified_subs)
        print(f"[+] Found {len(verified_subs)} verified subdomains")

    def certificate_transparency_lookup(self):
        """Query Certificate Transparency logs"""
        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            response = requests.get(url, timeout=self.timeout)
            data = response.json()
            
            for entry in data:
                name = entry['name_value']
                if self.target in name:
                    subdomains.update(name.split('\n'))
                    
        except Exception as e:
            print(f"      [-] CT log query failed: {e}")
            
        return subdomains

    def dns_bruteforce(self):
        """Bruteforce subdomains using wordlist"""
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
            executor.map(check_subdomain, self.subdomain_wordlist)
            
        return found_subdomains

    def search_engine_enumeration(self):
        """Extract subdomains from search engines"""
        subdomains = set()
        try:
            # Bing search
            url = f"https://www.bing.com/search?q=site:{self.target}"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(url, headers=headers, timeout=self.timeout)
            
            # Extract domains from search results
            pattern = f"([a-zA-Z0-9]+\\.){self.target}"
            matches = re.findall(pattern, response.text)
            subdomains.update([match[:-1] for match in matches])
            
        except Exception as e:
            print(f"      [-] Search engine enumeration failed: {e}")
            
        return subdomains

    def dns_zone_transfer(self):
        """Attempt DNS zone transfer"""
        subdomains = set()
        try:
            ns_servers = dns.resolver.resolve(self.target, 'NS')
            for ns in ns_servers:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns), self.target))
                    for name in zone.nodes.keys():
                        subdomains.add(f"{name}.{self.target}")
                except:
                    continue
        except:
            pass
            
        return subdomains

    def verify_subdomains(self, subdomains):
        """Verify subdomains are live and get their IPs"""
        verified = []
        
        def verify(subdomain):
            try:
                ip = socket.gethostbyname(subdomain)
                verified.append({'subdomain': subdomain, 'ip': ip})
            except:
                pass
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(verify, subdomains)
            
        return verified

    def port_scanning(self, ip=None):
        """Advanced port scanning with service detection"""
        if not ip:
            ip = self.results['ip_address']
            
        if not ip:
            print("[-] No IP address for port scanning")
            return
            
        print(f"\n[+] Scanning ports on {ip}...")
        
        def scan_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        service = self.get_service_info(ip, port)
                        self.results['open_ports'].append({
                            'port': port,
                            'service': service.get('name', 'unknown'),
                            'version': service.get('version', ''),
                            'banner': service.get('banner', '')
                        })
                        print(f"    Port {port}/tcp open - {service.get('name', 'unknown')}")
                        return port
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(scan_port, self.common_ports)

    def get_service_info(self, ip, port):
        """Get service banner and version information"""
        service_info = {'name': 'unknown', 'version': '', 'banner': ''}
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((ip, port))
                
                # Try to receive banner
                try:
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                    service_info['banner'] = banner
                    
                    # Common service detection
                    if port == 22:
                        service_info['name'] = 'ssh'
                        if 'SSH' in banner:
                            service_info['version'] = banner
                    elif port == 80 or port == 443:
                        service_info['name'] = 'http'
                        # Send HTTP request
                        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        http_banner = s.recv(1024).decode('utf-8', errors='ignore')
                        service_info['banner'] = http_banner
                except:
                    pass
                    
        except:
            pass
            
        return service_info

    def web_technology_detection(self):
        """Detect web technologies"""
        print(f"\n[+] Detecting web technologies...")
        
        schemes = ['http', 'https']
        for scheme in schemes:
            try:
                url = f"{scheme}://{self.target}"
                response = requests.get(url, timeout=self.timeout, verify=False)
                
                # Server header
                server = response.headers.get('Server', '')
                if server:
                    print(f"    Web Server: {server}")
                    self.results['web_technologies']['server'] = server
                
                # X-Powered-By header
                powered_by = response.headers.get('X-Powered-By', '')
                if powered_by:
                    print(f"    Powered By: {powered_by}")
                    self.results['web_technologies']['powered_by'] = powered_by
                
                # Content analysis
                content = response.text.lower()
                technologies = []
                
                if 'wordpress' in content or 'wp-content' in content:
                    technologies.append('WordPress')
                if 'drupal' in content:
                    technologies.append('Drupal')
                if 'joomla' in content:
                    technologies.append('Joomla')
                if 'react' in content:
                    technologies.append('React')
                if 'jquery' in content:
                    technologies.append('jQuery')
                if 'bootstrap' in content:
                    technologies.append('Bootstrap')
                
                if technologies:
                    print(f"    Detected: {', '.join(technologies)}")
                    self.results['web_technologies']['frameworks'] = technologies
                    
                break
                
            except Exception as e:
                continue

    def ssl_certificate_analysis(self):
        """Analyze SSL certificate"""
        print(f"\n[+] Analyzing SSL certificate...")
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Extract certificate information
                    subject = dict(x[0] for x in cert['subject'])
                    issuer = dict(x[0] for x in cert['issuer'])
                    
                    self.results['ssl_info'] = {
                        'subject': subject,
                        'issuer': issuer,
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'san': cert.get('subjectAltName', [])
                    }
                    
                    print(f"    Subject: {subject.get('commonName', 'N/A')}")
                    print(f"    Issuer: {issuer.get('organizationName', 'N/A')}")
                    print(f"    Expires: {cert['notAfter']}")
                    
        except Exception as e:
            print(f"    [-] SSL analysis failed: {e}")

    def directory_enumeration(self):
        """Directory and file bruteforce"""
        print(f"\n[+] Performing directory enumeration...")
        
        common_dirs = [
            'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin', 
            'cpanel', 'webmail', 'backup', 'uploads', 'images', 'css', 
            'js', 'api', 'doc', 'docs', 'test', 'demo', 'old', 'temp'
        ]
        
        found_dirs = []
        
        def check_directory(directory):
            for scheme in ['http', 'https']:
                try:
                    url = f"{scheme}://{self.target}/{directory}"
                    response = requests.get(url, timeout=2, verify=False, allow_redirects=False)
                    
                    if response.status_code in [200, 301, 302, 403]:
                        found_dirs.append({
                            'url': url,
                            'status_code': response.status_code,
                            'size': len(response.content)
                        })
                        print(f"    Found: {url} [{response.status_code}]")
                        break
                except:
                    continue
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_directory, common_dirs)
            
        self.results['directory_enum'] = found_dirs

    def vulnerability_scanning(self):
        """Basic vulnerability scanning"""
        print(f"\n[+] Performing basic vulnerability scan...")
        
        vulnerabilities = []
        
        # Check for common vulnerabilities
        checks = [
            self.check_http_methods,
            self.check_security_headers,
            self.check_exposed_files
        ]
        
        for check in checks:
            try:
                result = check()
                if result:
                    vulnerabilities.extend(result)
            except Exception as e:
                print(f"    [-] Vulnerability check failed: {e}")
        
        self.results['vulnerabilities'] = vulnerabilities

    def check_http_methods(self):
        """Check for dangerous HTTP methods"""
        vulns = []
        try:
            url = f"http://{self.target}"
            response = requests.options(url, timeout=self.timeout)
            allowed_methods = response.headers.get('allow', '')
            
            dangerous_methods = ['PUT', 'DELETE', 'TRACE']
            for method in dangerous_methods:
                if method in allowed_methods:
                    vulns.append(f"Dangerous HTTP method allowed: {method}")
                    print(f"    [!] Dangerous HTTP method: {method}")
                    
        except:
            pass
            
        return vulns

    def check_security_headers(self):
        """Check for missing security headers"""
        vulns = []
        try:
            url = f"https://{self.target}"
            response = requests.get(url, timeout=self.timeout, verify=False)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing protection',
                'Strict-Transport-Security': 'HSTS enforcement',
                'Content-Security-Policy': 'Content security policy'
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    vulns.append(f"Missing security header: {header} - {description}")
                    print(f"    [!] Missing security header: {header}")
                    
        except:
            pass
            
        return vulns

    def check_exposed_files(self):
        """Check for exposed sensitive files"""
        vulns = []
        sensitive_files = [
            '.env', '.git/config', 'backup.zip', 'database.sql',
            'wp-config.php', 'config.php', '.htaccess'
        ]
        
        def check_file(filename):
            for scheme in ['http', 'https']:
                try:
                    url = f"{scheme}://{self.target}/{filename}"
                    response = requests.get(url, timeout=2, verify=False)
                    
                    if response.status_code == 200:
                        vulns.append(f"Exposed sensitive file: {filename}")
                        print(f"    [!] Exposed file: {filename}")
                        break
                except:
                    continue
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_file, sensitive_files)
            
        return vulns

    def osint_gathering(self):
        """Gather OSINT information from various sources"""
        print(f"\n[+] Gathering OSINT information...")
        
        osint_data = {}
        
        # Shodan-like checks (without API)
        ip = self.results['ip_address']
        if ip:
            try:
                # Check if IP has any interesting services
                for port in [80, 443, 22, 21]:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        result = sock.connect_ex((ip, port))
                        if result == 0:
                            osint_data[f'port_{port}'] = 'open'
                        sock.close()
                    except:
                        pass
            except:
                pass
        
        self.results['osint_data'] = osint_data

    def generate_report(self, output_file=None):
        """Generate comprehensive report"""
        if not output_file:
            output_file = f"recon_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        print(f"\n[+] Generating report: {output_file}")
        
        # Save JSON report
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Print summary
        self.print_summary()
        
        return output_file

    def print_summary(self):
        """Print execution summary"""
        print("\n" + "="*60)
        print("📊 RECONNAISSANCE SUMMARY")
        print("="*60)
        print(f"Target: {self.target}")
        print(f"IP Address: {self.results['ip_address']}")
        print(f"Subdomains Found: {len(self.results['subdomains'])}")
        print(f"Open Ports: {len(self.results['open_ports'])}")
        print(f"Vulnerabilities Found: {len(self.results['vulnerabilities'])}")
        print(f"Web Technologies: {len(self.results['web_technologies'])}")
        print(f"DNS Records: {len(self.results['dns_records'])}")
        
        if self.results['vulnerabilities']:
            print("\n🚨 SECURITY ISSUES FOUND:")
            for vuln in self.results['vulnerabilities']:
                print(f"  • {vuln}")

    def run_full_scan(self):
        """Execute full reconnaissance scan"""
        start_time = time.time()
        
        try:
            self.banner()
            
            # Phase 1: Basic Recon
            ip = self.get_ip()
            self.whois_lookup()
            self.dns_enumeration()
            
            # Phase 2: Advanced Enumeration
            self.subdomain_enumeration()
            self.port_scanning(ip)
            
            # Phase 3: Web Assessment
            self.web_technology_detection()
            self.ssl_certificate_analysis()
            self.directory_enumeration()
            
            # Phase 4: Security Assessment
            self.vulnerability_scanning()
            self.osint_gathering()
            
            # Phase 5: Reporting
            elapsed_time = time.time() - start_time
            print(f"\n[+] Scan completed in {elapsed_time:.2f} seconds")
            
            return self.results
            
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
            return self.results
        except Exception as e:
            print(f"\n[-] Scan failed: {e}")
            return self.results

def main():
    parser = argparse.ArgumentParser(description="🔥 ULTIMATE RECON TOOL - All-in-One Reconnaissance Suite")
    parser.add_argument("target", help="Target domain or IP address")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads (default: 100)")
    parser.add_argument("-o", "--output", help="Output file for report")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds (default: 5)")
    
    args = parser.parse_args()
    
    # Legal disclaimer
    print("⚠️  LEGAL DISCLAIMER: This tool is for educational and authorized testing only.")
    print("   You must have explicit permission to scan the target system.")
    print("   The author is not responsible for any misuse of this tool.\n")
    
    consent = input("Do you have permission to scan this target? (y/N): ")
    if consent.lower() not in ['y', 'yes']:
        print("Scan aborted. Proper authorization is required.")
        sys.exit(1)
    
    # Initialize and run tool
    tool = UltimateReconTool(args.target, threads=args.threads, timeout=args.timeout)
    results = tool.run_full_scan()
    
    # Generate report
    if results:
        report_file = tool.generate_report(args.output)
        print(f"\n🎯 Report saved to: {report_file}")

if __name__ == "__main__":
    main()
