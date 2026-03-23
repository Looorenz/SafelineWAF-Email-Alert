# SafeLine WAF Monitoring System Integration [2026]
## The script integrates SafeLine WAF with a monitoring system and uses Bash and Python for implementation.

Make sure that SafeLine has the required dependencies installed:

```bash
docker exec safeline-pg psql --version
```

Create the required files in /opt/safeline-monitoring/bin:
```bash
mkdir -p /opt/safeline-monitoring/{bin,config,data,logs}
cd /opt/safeline-monitoring && touch bin/safeline_monitor.sh bin/safeline_mailer.sh
```

## Files to be included in /opt/safeline-monitoring

safeline_monitor.sh
```bash
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
```

safeline_mailer.sh
```bash
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
```

## Configuration Files

Configuration for database connection:

safeline.conf
```bash
# SafeLine Database Configuration
DB_HOST="safeline-pg"
DB_PORT="5432"
DB_USER="safeline-ce"
DB_PASSWORD="PASSWORD-SAFELINEPOSTGRESSDB"
DB_NAME="safeline-ce"

# Paths Configuration
PROJECT_DIR="/opt/safeline-monitoring"
MAPPING_FILE="$PROJECT_DIR/config/mappings.json"
LAST_ID_FILE="$PROJECT_DIR/data/last_event_id.txt"
LOG_FILE="$PROJECT_DIR/logs/attacks.jsonl"

# Log settings
LOG_LEVEL="INFO"
```

Configuration for SMTP email settings:

smtp.conf
```bash
SMTP_HOST="mail.example.com"
SMTP_PORT="587"
SMTP_USER="your-email@example.com"
SMTP_PASS="your-password"
FROM_EMAIL="alerts@example.com"
TO_EMAIL="admin@example.com"
```

Configuration for location mapping (province and city translations):

mappings.json
```json
{
  "provinces": {
    "普利亚大区": "Apulia",
    "...": "..."
  },
  "cities": {
    "福贾": "Foggia",
    "...": "..."
  }
}
```

After creating these files, make sure to execute the following command in the terminal to set the ownership and permissions correctly:

```bash
chown root:root /opt/safeline-monitoring/bin/safeline_monitor.sh /opt/safeline-monitoring/bin/safeline_mailer.sh && chmod 750 /opt/safeline-monitoring/bin/safeline_monitor.sh /opt/safeline-monitoring/bin/safeline_mailer.sh
```

## Directory Structure

```
/opt/safeline-monitoring/
├── bin/
│   ├── safeline_monitor.sh
│   └── safeline_mailer.sh
├── config/
│   ├── safeline.conf
│   ├── smtp.conf
│   └── mappings.json
├── data/
│   ├── last_event_id.txt
│   └── last_mail_id.txt
└── logs/
    ├── attacks.jsonl
    ├── monitor.log
    └── cron.log
```

## Manual Execution

Test the scripts manually:

```bash
# Run the monitor (reads attacks and sends emails)
/opt/safeline-monitoring/bin/safeline_monitor.sh

# Check the logs
tail -f /opt/safeline-monitoring/logs/monitor.log
```

## Cron Scheduling

Add to crontab for automatic monitoring:

```bash
# Every 5 minutes
*/5 * * * * /opt/safeline-monitoring/bin/safeline_monitor.sh >> /opt/safeline-monitoring/logs/cron.log 2>&1

# Every minute (intensive monitoring)
* * * * * /opt/safeline-monitoring/bin/safeline_monitor.sh >> /opt/safeline-monitoring/logs/cron.log 2>&1
```

Edit the crontab:

```bash
sudo crontab -e
```

## Data Format

JSON Structure (attacks.jsonl)

Each attack is recorded on a single JSON line:

```json
{
  "id": 42,
  "timestamp": "2024-03-21 15:23:45",
  "src_ip": "192.168.1.100",
  "host": "api.example.com",
  "url_path": "/api/login?id=1'",
  "dst_port": 443,
  "attack_type": 0,
  "attack_name": "SQL Injection",
  "risk_level": 3,
  "risk_name": "Critical",
  "action": 1,
  "action_name": "Block",
  "country": "Italy",
  "province": "Apulia",
  "city": "Foggia",
  "latitude": "41.4614",
  "longitude": "15.5542"
}
```

Supported Attack Types

| Code | Type | Description |
|------|------|-------------|
| 0 | SQL Injection | SQL Injection attempt |
| 1 | XSS | Cross-Site Scripting |
| 2 | Path Traversal | Directory traversal attempt |
| 3 | Command Injection | OS command injection |
| -3 | Malicious IP | Malicious IP address |

Risk Levels

| Level | Name |
|-------|------|
| 0 | Low |
| 1 | Medium |
| 2 | High |
| 3 | Critical |

## Important Note

[INFO] The tool will only trigger if the attack is actually detected in the SafeLine WAF database.

Attacks must be present in the mgt_detect_log_basic table of the SafeLine PostgreSQL database to be processed and alerted.
