#!/bin/bash
#
# SafeLine WAF Email Alert Script
# Sends email notifications for new attacks detected by the monitoring script
#

set -euo pipefail

source /opt/safeline-monitoring/config/smtp.conf

LAST_MAIL_ID_FILE="/opt/safeline-monitoring/data/last_mail_id.txt"
LOG_FILE="/opt/safeline-monitoring/logs/attacks.jsonl"
TEMP_DIR="/tmp/safeline_emails"

mkdir -p "$TEMP_DIR"

get_last_mail_id() {
    if [ -f "$LAST_MAIL_ID_FILE" ]; then
        cat "$LAST_MAIL_ID_FILE" 2>/dev/null | tr -d ' \n' || echo "0"
    else
        echo "0"
    fi
}

save_last_mail_id() {
    echo "$1" > "$LAST_MAIL_ID_FILE"
}

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

send_email() {
    local subject="$1"
    local body_file="$2"
    
    export SMTP_HOST SMTP_PORT SMTP_USER SMTP_PASS
    export FROM_EMAIL TO_EMAIL
    export EMAIL_SUBJECT="$subject"
    export EMAIL_BODY_FILE="$body_file"
    
    python3 << 'PYTHON'
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import sys

try:
    with open(os.environ['EMAIL_BODY_FILE'], 'r') as f:
        body = f.read()
    
    server = smtplib.SMTP(os.environ['SMTP_HOST'], int(os.environ['SMTP_PORT']))
    server.starttls()
    server.login(os.environ['SMTP_USER'], os.environ['SMTP_PASS'])
    
    msg = MIMEMultipart('alternative')
    msg['Subject'] = os.environ['EMAIL_SUBJECT']
    msg['From'] = os.environ['FROM_EMAIL']
    msg['To'] = os.environ['TO_EMAIL']
    msg.attach(MIMEText(body, 'html'))
    
    server.sendmail(os.environ['FROM_EMAIL'], os.environ['TO_EMAIL'], msg.as_string())
    server.quit()
    
    print("OK")
except Exception as e:
    print(f"ERROR: {str(e)}", file=sys.stderr)
    sys.exit(1)
PYTHON
}

format_email() {
    local id=$1 timestamp=$2 src_ip=$3 host=$4 url_path=$5
    local attack_name=$6 risk_name=$7 country=$8 province=$9 city=${10}
    
    cat << EOF
<!DOCTYPE html>
<html>
<head>
<style>
body { font-family: Arial, sans-serif; background-color: #f5f5f5; }
.container { background-color: white; padding: 20px; margin: 20px; border-radius: 5px; }
.header { background-color: #d32f2f; color: white; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
.header h2 { margin: 0; }
.detail { margin: 10px 0; }
.label { font-weight: bold; color: #333; }
.value { color: #666; }
.critical { color: #d32f2f; font-weight: bold; }
</style>
</head>
<body>
<div class="container">
<div class="header">
<h2>SafeLine WAF - Attack Detected</h2>
</div>
<div class="detail"><span class="label">ID:</span> <span class="value">$id</span></div>
<div class="detail"><span class="label">Time:</span> <span class="value">$timestamp</span></div>
<div class="detail"><span class="label">Attack Type:</span> <span class="critical">$attack_name</span></div>
<div class="detail"><span class="label">Risk Level:</span> <span class="critical">$risk_name</span></div>
<div class="detail"><span class="label">Source IP:</span> <span class="value">$src_ip</span></div>
<div class="detail"><span class="label">Target Host:</span> <span class="value">$host</span></div>
<div class="detail"><span class="label">URL Path:</span> <span class="value">$url_path</span></div>
<div class="detail"><span class="label">Location:</span> <span class="value">$city, $province, $country</span></div>
</div>
</body>
</html>
EOF
}

main() {
    log_message "Mailer started"
    
    last_mail_id=$(get_last_mail_id)
    log_message "Last sent ID: $last_mail_id"
    
    if [ ! -f "$LOG_FILE" ]; then
        log_message "Log file not found: $LOG_FILE"
        return 1
    fi
    
    while IFS= read -r json; do
        [ -z "$json" ] && continue
        
        id=$(echo "$json" | jq -r '.id' 2>/dev/null) || continue
        [ -z "$id" ] || [ "$id" = "null" ] && continue
        [ "$id" -le "$last_mail_id" ] && continue
        
        timestamp=$(echo "$json" | jq -r '.timestamp')
        src_ip=$(echo "$json" | jq -r '.src_ip')
        host=$(echo "$json" | jq -r '.host')
        url_path=$(echo "$json" | jq -r '.url_path')
        attack_name=$(echo "$json" | jq -r '.attack_name')
        risk_name=$(echo "$json" | jq -r '.risk_name')
        country=$(echo "$json" | jq -r '.country')
        province=$(echo "$json" | jq -r '.province')
        city=$(echo "$json" | jq -r '.city')
        
        log_message "Processing attack ID $id"
        
        subject="[SafeLine] $attack_name on $host"
        body_file="$TEMP_DIR/email_$id.html"
        
        format_email "$id" "$timestamp" "$src_ip" "$host" "$url_path" "$attack_name" "$risk_name" "$country" "$province" "$city" > "$body_file"
        
        result=$(send_email "$subject" "$body_file" 2>&1)
        rm -f "$body_file"
        
        if [ "$result" = "OK" ]; then
            log_message "Alert sent for attack ID $id"
            save_last_mail_id "$id"
        else
            log_message "Failed to send alert for attack ID $id: $result"
        fi
    done < "$LOG_FILE"
    
    log_message "Mailer completed"
}

main "$@"