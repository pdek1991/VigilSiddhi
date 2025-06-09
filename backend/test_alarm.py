from flask import Flask, jsonify
from flask_cors import CORS
import requests
import json
import logging
import urllib3
from datetime import datetime, timedelta
import pytz
import os

# Suppress insecure request warning for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging for better visibility
# Set level to DEBUG to see all detailed messages
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
# Enable CORS for all origins. In production, restrict this to your frontend's origin.
CORS(app)

# --- Load iLO server configurations from JSON files ---
CHANNEL_ILO_CONFIG_FILE = 'channel_ilo_config.json'
GLOBAL_ILO_CONFIG_FILE = 'global_ilo_config.json'

ILO_CREDENTIALS_MAP = {} # Maps IP to {username, password, type (e.g., 'VS_M')}
CHANNEL_DEVICE_IP_MAP = {} # Maps (channel_id, device_id) to ip
GLOBAL_COLLECTIVE_IP_MAP = {} # Maps collective_block_id to list of ips

def load_configs():
    """Loads iLO configurations from JSON files."""
    global ILO_CREDENTIALS_MAP, CHANNEL_DEVICE_IP_MAP, GLOBAL_COLLECTIVE_IP_MAP

    ILO_CREDENTIALS_MAP = {}
    CHANNEL_DEVICE_IP_MAP = {}
    GLOBAL_COLLECTIVE_IP_MAP = {
        "VS_M": [], # Collect all VS_M IPs from channels + additional
        "VS_P": [], # Collect all VS_P IPs from channels + additional
        "VS_B": []  # Collect all VS_B IPs from channels + additional
    }

    logging.info("--- Attempting to load iLO configuration files ---")
    # Print current working directory to verify file path
    logging.info(f"Current working directory: {os.getcwd()}")


    try:
        # Load channel iLO config
        channel_config_found = os.path.exists(CHANNEL_ILO_CONFIG_FILE)
        if channel_config_found:
            logging.info(f"Found channel iLO config file: {CHANNEL_ILO_CONFIG_FILE}")
            with open(CHANNEL_ILO_CONFIG_FILE, 'r') as f:
                channel_configs = json.load(f)
                logging.info(f"Successfully loaded {len(channel_configs)} channel configurations from {CHANNEL_ILO_CONFIG_FILE}.")
                logging.debug(f"Content of {CHANNEL_ILO_CONFIG_FILE}:\n{json.dumps(channel_configs, indent=2)}")
                for channel_data in channel_configs:
                    channel_id = channel_data.get('channel_id')
                    if channel_id is None:
                        logging.warning(f"Skipping channel config entry due to missing 'channel_id': {channel_data}")
                        continue
                    for device in channel_data.get('devices', []):
                        device_id = device.get('id')
                        ip = device.get('ip')
                        username = device.get('username')
                        password = device.get('password')
                        if all([device_id, ip, username, password]):
                            ILO_CREDENTIALS_MAP[ip] = {
                                "username": username,
                                "password": password,
                                "type": device_id # Store device type (e.g., "VS_M")
                            }
                            CHANNEL_DEVICE_IP_MAP[(channel_id, device_id)] = ip
                            logging.debug(f"Mapped Channel {channel_id}, Device {device_id} to IP {ip}. Added to ILO_CREDENTIALS_MAP and CHANNEL_DEVICE_IP_MAP.")
                            # Add to collective global map
                            if device_id in GLOBAL_COLLECTIVE_IP_MAP:
                                GLOBAL_COLLECTIVE_IP_MAP[device_id].append(ip)
                        else:
                            logging.warning(f"Skipping malformed device entry in channel {channel_id}: {device}")
        else:
            logging.error(f"Channel iLO config file NOT FOUND: {CHANNEL_ILO_CONFIG_FILE}. Please ensure it's in the same directory as the script or provide absolute path.")

        # Load global iLO config (for additional servers contributing to global blocks)
        global_config_found = os.path.exists(GLOBAL_ILO_CONFIG_FILE)
        if global_config_found:
            logging.info(f"Found global iLO config file: {GLOBAL_ILO_CONFIG_FILE}")
            with open(GLOBAL_ILO_CONFIG_FILE, 'r') as f:
                global_configs = json.load(f)
                logging.info(f"Successfully loaded {len(global_configs)} global configurations from {GLOBAL_ILO_CONFIG_FILE}.")
                logging.debug(f"Content of {GLOBAL_ILO_CONFIG_FILE}:\n{json.dumps(global_configs, indent=2)}")
                for group_data in global_configs:
                    group_type = group_data.get('type') # e.g., "VS_M" for GROUP_ILO_M
                    if group_type and group_type in GLOBAL_COLLECTIVE_IP_MAP:
                        for additional_ip_data in group_data.get('additional_ips', []):
                            ip = additional_ip_data.get('ip')
                            username = additional_ip_data.get('username')
                            password = additional_ip_data.get('password')
                            if all([ip, username, password]):
                                ILO_CREDENTIALS_MAP[ip] = {
                                    "username": username,
                                    "password": password,
                                    "type": group_type
                                }
                                # Add to the list only if it's not already there (to avoid duplicates if an IP is in both channel and global configs for the same type)
                                if ip not in GLOBAL_COLLECTIVE_IP_MAP[group_type]:
                                    GLOBAL_COLLECTIVE_IP_MAP[group_type].append(ip)
                                logging.debug(f"Mapped Global type {group_type} to additional IP {ip}. Added to ILO_CREDENTIALS_MAP and GLOBAL_COLLECTIVE_IP_MAP.")
                            else:
                                logging.warning(f"Skipping malformed additional IP entry for group {group_type}: {additional_ip_data}")
        else:
            logging.error(f"Global iLO config file NOT FOUND: {GLOBAL_ILO_CONFIG_FILE}. Please ensure it's in the same directory as the script or provide absolute path.")

        logging.info(f"Finished loading configs. Total iLO credentials loaded: {len(ILO_CREDENTIALS_MAP)}")
        if not ILO_CREDENTIALS_MAP:
            logging.critical("ILO_CREDENTIALS_MAP is EMPTY after loading configs. This means no iLOs will be monitored!")

        logging.debug(f"Final ILO_CREDENTIALS_MAP: {json.dumps(ILO_CREDENTIALS_MAP, indent=2)}")
        # Convert tuple keys to string for JSON dumping as JSON keys must be strings
        logging.debug(f"Final CHANNEL_DEVICE_IP_MAP: {json.dumps({str(k): v for k, v in CHANNEL_DEVICE_IP_MAP.items()}, indent=2)}")
        logging.debug(f"Final GLOBAL_COLLECTIVE_IP_MAP: {json.dumps(GLOBAL_COLLECTIVE_IP_MAP, indent=2)}")

    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON config file. Please check JSON syntax: {e}")
        logging.exception("JSON decoding error details:") # Log full traceback
    except Exception as e:
        logging.exception(f"An unexpected error occurred while loading configs: {e}")

load_configs() # Load configs on startup

# --- Helper functions (same as before) ---

def get_alarm_severity_priority(severity):
    """
    Assigns a numeric priority to alarm severities for comparison.
    Higher number means higher severity.
    """
    severity_lower = str(severity).lower()
    if severity_lower == "critical":
        return 4
    elif severity_lower == "warning":
        return 3
    elif severity_lower == "ok":
        return 1
    elif severity_lower == "informational":
        return 0 # Informational is lowest priority
    else:
        return 2 # Unknown/Other falls between warning and OK

def map_severity_to_dashboard_status(severity):
    """
    Maps Redfish severity to dashboard status codes ('ok', 'warning', 'alarm', 'unknown').
    """
    priority = get_alarm_severity_priority(severity)
    if priority == 4: # Critical
        return "alarm"
    elif priority == 3: # Warning
        return "warning"
    elif priority == 1 or priority == 0: # OK or Informational
        return "ok"
    else: # Unknown or other
        return "unknown"

def is_entry_active(entry):
    """
    Checks if an IML entry is considered 'active' (not repaired).
    """
    repaired = entry.get("Oem", {}).get("Hpe", {}).get("Repaired", True)
    return not repaired  # Active if Repaired is False

def is_within_last_x_days(timestamp, days=30):
    """
    Checks if a timestamp is within the last X days.
    """
    try:
        # Expected format from iLO is typically ISO 8601 with 'Z' for UTC
        log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=pytz.UTC)
        return log_time >= datetime.utcnow().replace(tzinfo=pytz.UTC) - timedelta(days=days)
    except ValueError:
        logging.warning(f"Invalid timestamp format encountered: {timestamp}")
        return False
    except Exception as e:
        logging.error(f"Error checking timestamp: {e}")
        return False

def get_active_iml_alarms(ilo_ip, username, password):
    """
    Fetches, filters, and dedupes active IML alarms for a given iLO.
    Returns a tuple: (highest_severity_status, list_of_active_alarms)
    """
    IML_URL = f"https://{ilo_ip}/redfish/v1/Systems/1/LogServices/IML/Entries"
    active_alarms = []
    latest_entries_by_message = {}
    highest_overall_priority = 0 # Corresponds to 'Informational' or lower

    logging.info(f"[{ilo_ip}] Fetching IML entries from {IML_URL}")

    try:
        session = requests.Session()
        session.auth = (username, password)
        session.verify = False  # Disable SSL verification (use with caution!)
        session.timeout = 15 # Increased timeout for potentially slower iLO responses

        response = session.get(IML_URL)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        entries = response.json().get("Members", [])
        logging.info(f"[{ilo_ip}] Successfully fetched {len(entries)} IML entries.")

        for entry in entries:
            created_timestamp = entry.get("Created", "")
            # Only consider entries within the last 30 days and those that are active
            if not is_within_last_x_days(created_timestamp, days=30) or not is_entry_active(entry):
                continue

            message = entry.get("Message", "No message")
            severity = entry.get("Severity", "Unknown")

            try:
                created_time_dt = datetime.strptime(created_timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=pytz.UTC)
            except ValueError:
                logging.warning(f"[{ilo_ip}] Skipping IML entry due to invalid timestamp: {created_timestamp}")
                continue # Skip entry if timestamp is invalid

            # Deduplicate by message, keeping the latest entry
            if message in latest_entries_by_message:
                existing_item = latest_entries_by_message[message]
                if created_time_dt > existing_item['created_time_dt']:
                    latest_entries_by_message[message] = {
                        'entry': entry,
                        'created_time_dt': created_time_dt
                    }
            else:
                latest_entries_by_message[message] = {
                    'entry': entry,
                    'created_time_dt': created_time_dt
                }

        # Process the deduplicated, active, and recent entries
        for item in latest_entries_by_message.values():
            entry = item['entry']
            timestamp_str = entry.get("Created", "N/A")
            severity = entry.get("Severity", "Unknown")
            message = entry.get("Message", "No message")

            active_alarms.append({
                "server_ip": ilo_ip,
                "message": message,
                "severity": severity,
                "timestamp": timestamp_str
            })

            # Determine the highest priority among active alarms
            current_alarm_priority = get_alarm_severity_priority(severity)
            if current_alarm_priority > highest_overall_priority:
                highest_overall_priority = current_alarm_priority

    except requests.exceptions.Timeout:
        logging.error(f"[{ilo_ip}] Connection timed out while fetching IML logs.")
        return "unknown", []
    except requests.exceptions.ConnectionError as e:
        logging.error(f"[{ilo_ip}] Connection error while fetching IML logs: {e}")
        return "unknown", []
    except requests.exceptions.HTTPError as e:
        logging.error(f"[{ilo_ip}] HTTP error {e.response.status_code}: {e.response.reason} during IML fetch. Response: {e.response.text[:200]}...")
        return "unknown", []
    except json.JSONDecodeError as e:
        logging.error(f"[{ilo_ip}] Failed to parse JSON response from IML: {e}")
        return "unknown", []
    except Exception as e:
        logging.exception(f"[{ilo_ip}] An unexpected error occurred during IML collection.")
        return "unknown", []
    finally:
        if 'session' in locals():
            session.close()

    # Sort active alarms by timestamp descending
    active_alarms.sort(key=lambda x: datetime.strptime(x['timestamp'], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=pytz.UTC), reverse=True)

    # Map the highest priority found to the dashboard status
    overall_status_for_dashboard = map_severity_to_dashboard_status(
        next((s for s, p in [("Critical", 4), ("Warning", 3), ("Unknown", 2), ("OK", 1), ("Informational", 0)] if p == highest_overall_priority), "Unknown")
    )

    logging.info(f"[{ilo_ip}] Final IML status determined: {overall_status_for_dashboard} with {len(active_alarms)} active alarms.")
    return overall_status_for_dashboard, active_alarms

# --- API Endpoints ---

@app.route('/get_ilo_status/<string:channel_id_str>/<string:device_id>', methods=['GET'])
def get_ilo_status(channel_id_str, device_id):
    """
    Flask endpoint to get the status and active alarms of a specific iLO server
    for a given channel and device (e.g., VS_M).
    """
    try:
        channel_id = int(channel_id_str)
    except ValueError:
        logging.error(f"API CALL: Received invalid channel_id_str: '{channel_id_str}'. Must be an integer.")
        return jsonify({"status": "error", "message": "Invalid channel_id", "alarms": []}), 400

    logging.debug(f"API CALL: Request received for (Channel: {channel_id}, Device: {device_id})")
    ip = CHANNEL_DEVICE_IP_MAP.get((channel_id, device_id))
    if not ip:
        logging.warning(f"API CALL: IP not found in CHANNEL_DEVICE_IP_MAP for Channel {channel_id}, Device {device_id}. Returning unknown.")
        logging.debug(f"Current CHANNEL_DEVICE_IP_MAP keys: {list(CHANNEL_DEVICE_IP_MAP.keys())}")
        return jsonify({"status": "unknown", "message": f"iLO IP not configured for Channel {channel_id} Device {device_id}", "alarms": []})

    credentials = ILO_CREDENTIALS_MAP.get(ip)
    if not credentials:
        logging.error(f"API CALL: Credentials not found in ILO_CREDENTIALS_MAP for iLO IP: {ip}. This means config file is missing credentials for this IP.")
        return jsonify({"status": "error", "message": f"iLO IP {ip} configured, but credentials missing", "alarms": []}), 404

    username = credentials['username']
    password = credentials['password']

    overall_status, active_alarms = get_active_iml_alarms(ip, username, password)

    return jsonify({
        "ip": ip,
        "status": overall_status, # 'ok', 'warning', 'alarm', 'unknown'
        "alarms": active_alarms # List of active alarms
    })

@app.route('/get_collective_ilo_status/<string:block_type>', methods=['GET'])
def get_collective_ilo_status(block_type):
    """
    Flask endpoint to get the collective status and all active alarms
    for a group of iLO servers (e.g., all VS_M servers).
    """
    logging.debug(f"API CALL: Request received for collective block type: {block_type}")
    ips_to_check = GLOBAL_COLLECTIVE_IP_MAP.get(block_type)

    if not ips_to_check:
        logging.warning(f"API CALL: No IPs configured in GLOBAL_COLLECTIVE_IP_MAP for collective block type: {block_type}. Returning unknown.")
        logging.debug(f"Current GLOBAL_COLLECTIVE_IP_MAP keys: {list(GLOBAL_COLLECTIVE_IP_MAP.keys())}")
        return jsonify({"status": "unknown", "message": f"No IPs configured for collective block type {block_type}", "alarms": []})

    highest_overall_priority = 0
    all_active_alarms = []

    for ip in ips_to_check:
        credentials = ILO_CREDENTIALS_MAP.get(ip)
        if not credentials:
            logging.warning(f"API CALL: Credentials not found in ILO_CREDENTIALS_MAP for collective iLO IP: {ip}. Skipping.")
            continue

        username = credentials['username']
        password = credentials['password']

        current_status, current_alarms = get_active_iml_alarms(ip, username, password)

        # Update highest overall priority
        current_priority = get_alarm_severity_priority(current_status)
        if current_priority > highest_overall_priority:
            highest_overall_priority = current_priority

        all_active_alarms.extend(current_alarms)

    # Sort all collected alarms by timestamp descending
    all_active_alarms.sort(key=lambda x: datetime.strptime(x['timestamp'], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=pytz.UTC), reverse=True)

    collective_dashboard_status = map_severity_to_dashboard_status(
        next((s for s, p in [("Critical", 4), ("Warning", 3), ("Unknown", 2), ("OK", 1), ("Informational", 0)] if p == highest_overall_priority), "Unknown")
    )

    logging.info(f"API CALL: Collective status for {block_type}: {collective_dashboard_status} with {len(all_active_alarms)} alarms.")
    return jsonify({
        "block_type": block_type,
        "status": collective_dashboard_status,
        "alarms": all_active_alarms
    })


if __name__ == '__main__':
    # Test code to print alarms locally
    print("\n--- Running Local Alarm Test ---")

    # Pick a sample IP from the loaded configurations for testing
    sample_ip = None
    # Prioritize finding a VS_M from Channel 1 if available
    if (1, 'VS_M') in CHANNEL_DEVICE_IP_MAP:
        sample_ip = CHANNEL_DEVICE_IP_MAP[(1, 'VS_M')]
    else:
        # Fallback to any IP found in ILO_CREDENTIALS_MAP
        for ip, creds in ILO_CREDENTIALS_MAP.items():
            sample_ip = ip
            break

    if sample_ip:
        sample_username = ILO_CREDENTIALS_MAP[sample_ip]['username']
        sample_password = ILO_CREDENTIALS_MAP[sample_ip]['password']
        print(f"Attempting to fetch alarms for sample IP: {sample_ip}")

        test_status, test_alarms = get_active_iml_alarms(sample_ip, sample_username, sample_password)

        print(f"\nOverall Status for {sample_ip}: {test_status}")
        print("\nActive Alarms:")
        if test_alarms:
            for alarm in test_alarms:
                print(f"  IP: {alarm['server_ip']}, Message: {alarm['message']}, Severity: {alarm['severity']}, Time: {alarm['timestamp']}")
        else:
            print("  No active alarms found for this IP.")
    else:
        print("No iLO IPs configured in channel_ilo_config.json or global_ilo_config.json to run local test.")

    print("\n--- Starting Flask App ---")
    # Run the Flask app on port 5000
    app.run(host='0.0.0.0', port=5000, debug=False)
