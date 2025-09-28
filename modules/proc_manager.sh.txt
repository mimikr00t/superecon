#!/usr/bin/env bash
# proc_manager.sh — Interactive process inspector + kill + optional delete executable

set -u
LOGFILE="${LOGFILE:-/var/log/proc_manager.log}"
TMP="/tmp/proc_manager.$$"
BLACKLIST_PATHS=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/lib" "/lib64" "/etc" "/proc" "/sys" "/dev" "/root" "/boot")
KEYWORDS=(python node nodejs php ruby java go perl bash sh ksh zsh "python3")

die() { echo "Error: $*" >&2; exit 1; }
info(){ echo -e "\e[1;34m[INFO]\e[0m $*"; }
warn(){ echo -e "\e[1;33m[WARN]\e[0m $*"; }
ok(){ echo -e "\e[1;32m[OK]\e[0m $*"; }
log() { echo "[$(date --iso-8601=seconds)] $*" >> "$LOGFILE"; }

ensure_tools() {
  for cmd in ps awk sed readlink pgrep; do
    command -v "$cmd" >/dev/null || die "Missing tool: $cmd"
  done
}

build_list() {
  > "$TMP"
  ps -eo pid,uid,user:16,etimes,args --no-headers | while read -r pid uid user etime args_rest; do
    [ -z "$pid" ] || [ -z "$args_rest" ] && continue
    cmdbase=$(echo "$args_rest" | awk '{print $1}')
    matched=false
    for kw in "${KEYWORDS[@]}"; do
      echo "$args_rest" | grep -iq "$kw" && matched=true && break
      [ -x "$cmdbase" ] && basename "$cmdbase" | grep -iq "$kw" && matched=true && break
    done
    [ "$FILTER_MODE" = "all" ] || [ "$matched" = true ] && printf "%s\t%s\t%s\t%s\t%s\n" "$pid" "$uid" "$user" "$etime" "$args_rest" >> "$TMP"
  done
}

show_menu() {
  echo -e "\n================ Process Manager ================\nLog: $LOGFILE\n"
  echo "Choose listing mode:"
  echo "  1) Show likely programming-language processes"
  echo "  2) Show ALL processes"
  echo "  q) Quit"
  read -rp "> " choice
  case "$choice" in
    1) FILTER_MODE="lang";;
    2) FILTER_MODE="all";;
    q|Q) cleanup_and_exit;;
    *) echo "Invalid"; show_menu;;
  esac

  build_list
  [ ! -s "$TMP" ] && echo "No matching processes found." && cleanup_and_exit

  echo -e "\nIndex | PID   | UID | USER            | ELAPSED(s) | COMMAND"
  echo "---------------------------------------------------------------"
  nl -ba -w3 -s'. ' "$TMP" | awk -F'\t' '{printf "%4s | %5s | %3s | %-15s | %10s | %s\n", $1, $2, $3, $3, $4, $5}'
  interact_loop
}

interact_loop() {
  echo -e "\nOptions:\n  <index> - inspect process\n  r - refresh\n  q - quit"
  while true; do
    read -rp "proc-mgr> " cmd
    case "$cmd" in
      r) build_list; show_entries;;
      q) cleanup_and_exit;;
      '') ;;
      *) [[ "$cmd" =~ ^[0-9]+$ ]] && inspect_by_index "$cmd" || echo "Unknown input";;
    esac
  done
}

show_entries() {
  echo -e "\nIndex | PID   | UID | USER            | ELAPSED(s) | COMMAND"
  echo "---------------------------------------------------------------"
  nl -ba -w3 -s'. ' "$TMP" | awk -F'\t' '{printf "%4s | %5s | %3s | %-15s | %10s | %s\n", $1, $2, $3, $3, $4, $5}'
}

get_line_by_index() { sed -n "${1}p" "$TMP"; }

inspect_by_index() {
  line="$(get_line_by_index "$1")"
  [ -z "$line" ] && echo "No entry at index $1" && return
  pid=$(awk -F'\t' '{print $1}' <<<"$line")
  uid=$(awk -F'\t' '{print $2}' <<<"$line")
  user=$(awk -F'\t' '{print $3}' <<<"$line")
  etime=$(awk -F'\t' '{print $4}' <<<"$line")
  cmdline=$(awk -F'\t' '{ $1=""; $2=""; $3=""; $4=""; sub("\t\t\t", ""); print substr($0,2) }' <<<"$line")

  echo -e "\n------ DETAILS for PID $pid ------"
  echo "User: $user (UID $uid)"
  echo "Elapsed (s): $etime"
  echo "Cmdline: $cmdline"

  exe_path=$(readlink -f /proc/$pid/exe 2>/dev/null || echo "not available")
  echo "Executable path: $exe_path"

  unitname=$(grep -Eo '[a-zA-Z0-9_.-]+\.service' /proc/$pid/cgroup 2>/dev/null | head -n1)

  command -v lsof >/dev/null && echo -e "\nOpen sockets:" && sudo lsof -nP -p "$pid" | sed -n '1,7p'

  echo -e "\nActions:\n  1) SIGTERM\n  2) SIGKILL\n  3) Stop systemd unit ($unitname)\n  4) Delete executable\n  b) Back"
  read -rp "Choose action: " act
  case "$act" in
    1) do_kill "$pid" "TERM";;
    2) do_kill "$pid" "KILL";;
    3) [ -n "$unitname" ] && stop_and_disable_unit "$unitname";;
    4) attempt_delete_file "$exe_path" "$uid" "$user";;
    b|B) return;;
    *) echo "Unknown action";;
  esac
}

do_kill() {
  pid="$1"; mode="$2"
  kill -0 "$pid" 2>/dev/null || { echo "Process $pid not found."; return; }
  owner_uid=$(ps -o uid= -p "$pid" | tr -d ' ')
  [ "$owner_uid" = "0" ] && read -rp "Type 'YES I KNOW' to kill root process: " conf && [ "$conf" != "YES I KNOW" ] && return
  sudo kill "-$mode" "$pid" && ok "Sent SIG$mode to $pid" || warn "Failed to kill $pid"
  log "Killed PID $pid with SIG$mode"
}

stop_and_disable_unit() {
  unit="$1"
  read -rp "Stop and disable $unit? (y/N): " yn
  [[ "$yn" =~ ^[Yy]$ ]] || return
  sudo systemctl stop "$unit" && ok "Stopped $unit"
  sudo systemctl disable "$unit" && ok "Disabled $unit"
  log "Stopped & disabled $unit"
}

is_under_blacklist() {
  for b in "${BLACKLIST_PATHS[@]}"; do [[ "$1" == "$b"* ]] && return 0; done
  return 1
}

attempt_delete_file() {
  path="$1"; [ -z "$path" ] && return
  resolved=$(readlink -f "$path" 2>/dev/null || echo "$path")
  is_under_blacklist "$resolved" && warn "Protected path: $resolved" && return
  echo "About to delete: $resolved"
  read -rp "Type DELETE to confirm: " confirm
  [ "$confirm" != "DELETE" ] && echo "Cancelled." && return
  pids_using=$(lsof -t "$resolved" 2>/dev/null)
  [ -n "$pids_using" ] && read -rp "Kill PIDs using file? (y/N): " yn && [[ "$yn" =~ ^[Yy]$ ]] && for pk in $pids_using; do sudo kill -9 "$pk"; done
  sudo rm -f "$resolved" && ok "Deleted: $resolved" || warn "Failed to delete: $resolved"
  log "Deleted $resolved"
}

cleanup_and_exit() {
  rm -f "$TMP"
  echo "Exiting. Log saved to $LOGFILE"
  exit 0
}

# main
ensure_tools
touch "$LOGFILE" 2>/dev/null || true
FILTER_MODE="lang"
show_menu
