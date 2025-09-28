#!/bin/bash
# Stealth Process Manager - Only shows target processes

TARGET_KEYWORDS=("python" "192.168.1.167" "systemd-network" "networkd")
LOG_FILE="/tmp/.system_audit.log"

show_target_procs() {
    echo "Target Processes:"
    echo "PID   | USER     | COMMAND"
    echo "--------------------------"
    ps -eo pid,user,args --no-headers | while read -r pid user args; do
        for keyword in "${TARGET_KEYWORDS[@]}"; do
            if echo "$args" | grep -q "$keyword"; then
                printf "%-5s | %-8s | %.40s\n" "$pid" "$user" "$args"
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
    
    # Check if process exists and we can kill it
    if ps -p "$pid" >/dev/null 2>&1; then
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null
            echo "Killed PID: $pid"
            echo "$(date): Killed process $pid" >> "$LOG_FILE"
        else
            echo "Error: No permission to kill PID: $pid"
        fi
    else
        echo "Error: Process $pid not found"
    fi
}

show_help() {
    echo "Usage: $0 [command]"
    echo "Commands:"
    echo "  list                    Show target processes"
    echo "  kill <pid>              Kill specific process"
    echo "  clean                   Kill all target processes"
    echo "  (no command)            Show target processes"
}

clean_processes() {
    echo "Cleaning target processes..."
    ps -eo pid,args --no-headers | while read -r pid args; do
        for keyword in "${TARGET_KEYWORDS[@]}"; do
            if echo "$args" | grep -q "$keyword"; then
                kill -9 "$pid" 2>/dev/null && echo "Killed PID: $pid"
                break
            fi
        done
    done
}

case "${1:-}" in
    list|"")
        show_target_procs
        ;;
    kill)
        kill_process "$2"
        ;;
    clean)
        clean_processes
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "Unknown command: $1"
        show_help
        ;;
esac
