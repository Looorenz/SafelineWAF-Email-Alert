#!/bin/bash
#
# SafeLine WAF Monitoring Script
# Reads attack logs from SafeLine PostgreSQL database and stores them as JSON
#

set -euo pipefail

source /opt/safeline-monitoring/config/safeline.conf

LOG_FILE="$PROJECT_DIR/logs/attacks.jsonl"
MAILER_SCRIPT="$PROJECT_DIR/bin/safeline_mailer.sh"

get_last_id() {
    if [ -f "$LAST_ID_FILE" ]; then
        cat "$LAST_ID_FILE" 2>/dev/null | tr -d ' \n' || echo "0"
    else
        echo "0"
    fi
}

save_last_id() {
    echo "$1" > "$LAST_ID_FILE"
}

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

translate_location() {
    local type=$1
    local value=$2
    
    python3 << PYTHON
import json
with open("$MAPPING_FILE") as f:
    mapping = json.load(f)
print(mapping.get("$type", {}).get('$value', '$value'))
PYTHON
}

map_attack_type() {
    case "$1" in
        0) echo "SQL Injection" ;;
        1) echo "XSS" ;;
        2) echo "Path Traversal" ;;
        3) echo "Command Injection" ;;
        -3) echo "Malicious IP" ;;
        *) echo "Other" ;;
    esac
}

map_risk_level() {
    case "$1" in
        0) echo "Low" ;;
        1) echo "Medium" ;;
        2) echo "High" ;;
        3) echo "Critical" ;;
        *) echo "Unknown" ;;
    esac
}

map_action() {
    case "$1" in
        0) echo "Pass" ;;
        1) echo "Block" ;;
        *) echo "Unknown" ;;
    esac
}

main() {
    log_message "Monitor started"
    
    last_id=$(get_last_id)
    log_message "Last processed ID: $last_id"
    
    attacks=$(sudo docker exec safeline-pg psql -U "$DB_USER" -d "$DB_NAME" -A -F'|' -t -c "
        SELECT id, updated_at, src_ip, host, url_path, dst_port, attack_type, risk_level, action, country, province, city, lat, lng
        FROM mgt_detect_log_basic
        WHERE id > $last_id
        ORDER BY id ASC;" 2>/dev/null)
    
    if [ -z "$attacks" ]; then
        log_message "No new attacks"
        return 0
    fi
    
    log_message "Processing attacks..."
    
    mapfile -t attack_lines <<< "$attacks"
    last_processed_id="$last_id"
    has_new_attacks=0
    
    for line in "${attack_lines[@]}"; do
        IFS='|' read -r id updated_at src_ip host url_path dst_port attack_type risk_level action country province city lat lng <<< "$line"
        
        province=$(translate_location "provinces" "$province")
        city=$(translate_location "cities" "$city")
        attack_name=$(map_attack_type "$attack_type")
        risk_name=$(map_risk_level "$risk_level")
        action_name=$(map_action "$action")
        
        json="{\"id\":$id,\"timestamp\":\"$updated_at\",\"src_ip\":\"$src_ip\",\"host\":\"$host\",\"url_path\":\"$url_path\",\"dst_port\":$dst_port,\"attack_type\":$attack_type,\"attack_name\":\"$attack_name\",\"risk_level\":$risk_level,\"risk_name\":\"$risk_name\",\"action\":$action,\"action_name\":\"$action_name\",\"country\":\"$country\",\"province\":\"$province\",\"city\":\"$city\",\"latitude\":\"$lat\",\"longitude\":\"$lng\"}"
        
        echo "$json" | sudo tee -a "$LOG_FILE" > /dev/null
        log_message "Attack ID $id logged"
        
        last_processed_id="$id"
        has_new_attacks=1
    done
    
    save_last_id "$last_processed_id"
    log_message "Saved. Last ID: $last_processed_id"
    
    if [ $has_new_attacks -eq 1 ]; then
        log_message "Sending alerts..."
        sudo "$MAILER_SCRIPT" >> "$PROJECT_DIR/logs/monitor.log" 2>&1
    fi
}

main "$@"