#!/bin/bash
# Advanced Process Manager
# Version: 2.1

LOG_FILE="/tmp/.system_audit.log"
TARGET_KEYWORDS=("python3.*networkd" "192.168.1.167" "systemd-network" "watcher.py")

log_event() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
}

show_target_processes() {
    echo "Advanced Process Manager"
    echo "========================"
    echo "PID   | USER     | CPU | MEM | COMMAND"
    echo "--------------------------------------"
    
    # Get process information with better formatting
    ps -eo pid,user,pcpu,pmem,args --sort=-pcpu | while read -r pid user pcpu pmem args; do
        for keyword in "${TARGET_KEYWORDS[@]}"; do
            if echo "$args" | grep -qE "$keyword"; then
                printf "%-5s | %-8s | %-3s | %-3s | %.45s\n" \
                       "$pid" "$user" "$pcpu" "$pmem" "$args"
                break
            fi
        done
    done
}

kill_process() {
    local pid="$1"
    if [ -z "$pid" ]; then
        echo "Error: No PID specified"
        return 1
    fi
    
    if ps -p "$pid" >/dev/null 2>&1; then
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null
            echo "Killed PID: $pid"
            log_event "Killed process: $pid"
        else
            echo "Error: No permission to kill PID: $pid"
        fi
    else
        echo "Error: Process $pid not found"
    fi
}

clean_system() {
    echo "[+] Cleaning target processes..."
    
    # Kill processes
    ps -eo pid,args --no-headers | while read -r pid args; do
        for keyword in "${TARGET_KEYWORDS[@]}"; do
            if echo "$args" | grep -qE "$keyword"; then
                kill -9 "$pid" 2>/dev/null && echo "Killed PID: $pid"
                break
            fi
        done
    done
    
    # Cleanup files
    find /usr/lib/systemd/systemd-network /lib/modules/.cache /var/tmp/.systemd \
        -name "networkd" -type f -delete 2>/dev/null
    
    # Remove persistence
    systemctl stop systemd-networkd.service 2>/dev/null
    systemctl disable systemd-networkd.service 2>/dev/null
    crontab -l 2>/dev/null | grep -v "networkd" | crontab - 2>/dev/null
    
    echo "[+] System cleanup completed"
}

show_help() {
    echo "Usage: $0 [command]"
    echo "Commands:"
    echo "  list                    Show target processes"
    echo "  kill <pid>              Kill specific process"
    echo "  clean                   Clean all target artifacts"
    echo "  monitor                 Continuous monitoring mode"
    echo "  (no command)            Show target processes"
}

monitor_mode() {
    echo "[+] Starting monitoring mode (Ctrl+C to stop)"
    while true; do
        clear
        show_target_processes
        echo
        echo "Monitoring... (Refreshing in 5 seconds)"
        sleep 5
    done
}

case "${1:-}" in
    list|"")
        show_target_processes
        ;;
    kill)
        kill_process "$2"
        ;;
    clean)
        clean_system
        ;;
    monitor)
        monitor_mode
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "Unknown command: $1"
        show_help
        ;;
esac
