import requests
from requests.auth import HTTPBasicAuth
from datetime import datetime, timedelta
import pytz

# Configuration
ILO_IP = '172.19.180.65'        # Replace with your iLO IP
USERNAME = 'Administrator'      # Replace with your iLO username
PASSWORD = 'Sony@2024!'          # Replace with your iLO password
IML_URL = f"https://{ILO_IP}/redfish/v1/Systems/1/LogServices/IML/Entries"

# Disable SSL warnings (self-signed certs)
requests.packages.urllib3.disable_warnings()

def get_recent_iml_entries():
    try:
        response = requests.get(
            IML_URL,
            auth=HTTPBasicAuth(USERNAME, PASSWORD),
            headers={"Accept": "application/json"},
            verify=False
        )

        if response.status_code != 200:
            print(f"[!] Failed to fetch IML logs: HTTP {response.status_code}")
            return []

        entries = response.json().get("Members", [])
        return entries

    except Exception as e:
        print(f"[!] Error while fetching IML logs: {e}")
        return []

def is_entry_active(entry):
    repaired = entry.get("Oem", {}).get("Hpe", {}).get("Repaired", True)
    return not repaired  # Active if Repaired is False

def is_within_last_30_days(timestamp):
    try:
        log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=pytz.UTC)
        return log_time >= datetime.utcnow().replace(tzinfo=pytz.UTC) - timedelta(days=5)
    except Exception:
        return False

def main():
    entries = get_recent_iml_entries()
    print(f"\n🔍 Checking Active Alarms (Last 30 Days) on iLO IP: {ILO_IP}\n{'-'*70}")

    latest_entries_by_message = {}

    for entry in entries:
        created = entry.get("Created", "")
        if not is_within_last_30_days(created):
            continue

        if not is_entry_active(entry):
            continue

        message = entry.get("Message", "No message")
        # Parse the created timestamp for comparison
        try:
            created_time = datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=pytz.UTC)
        except Exception:
            # If timestamp invalid, skip this entry
            continue

        # Check if this message is seen before and compare timestamps
        if message in latest_entries_by_message:
            existing_time = latest_entries_by_message[message]['created_time']
            if created_time > existing_time:
                # Replace with newer entry
                latest_entries_by_message[message] = {
                    'entry': entry,
                    'created_time': created_time
                }
        else:
            # First time seeing this message
            latest_entries_by_message[message] = {
                'entry': entry,
                'created_time': created_time
            }

    if not latest_entries_by_message:
        print("✅ No active alarms in the last 30 days.")
        return

    # Print the deduplicated active alarms, sorted by timestamp descending
    sorted_entries = sorted(
        latest_entries_by_message.values(),
        key=lambda x: x['created_time'],
        reverse=True
    )

    for item in sorted_entries:
        entry = item['entry']
        timestamp = entry.get("Created")
        severity = entry.get("Oem", {}).get("Hpe", {}).get("Severity", "Unknown")
        message = entry.get("Message", "No message")
        print(f"[{timestamp}] Severity: {severity} | {message}")

if __name__ == "__main__":
    main()
