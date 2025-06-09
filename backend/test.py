from flask import Flask, jsonify
from flask_cors import CORS
import requests
import json
import logging
import urllib3
from datetime import datetime, timedelta
import pytz
import os
import time
import random
import functools
from concurrent.futures import ThreadPoolExecutor

# Suppress insecure request warning for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging for better visibility
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
# Enable CORS for all origins. In production, restrict this to your frontend's origin.
CORS(app)

# --- Configuration for iLO devices and their mapping ---
# In a real application, these configurations would be loaded from a secure database
# or environment variables, not static JSON files, especially credentials.

CHANNEL_ILO_CONFIG_FILE = 'channel_ilo_config.json'
GLOBAL_ILO_CONFIG_FILE = 'global_ilo_config.json'

ILO_CREDENTIALS_MAP = {} # Maps IP to {username, password, type (e.g., 'VS_M')}
CHANNEL_DEVICE_IP_MAP = {} # Maps (channel_id, device_id) to ip
GLOBAL_COLLECTIVE_IP_MAP = {} # Maps collective_block_id (e.g., "VS_M") to list of ips
IP_TO_CHANNEL_DEVICE_LOOKUP = {} # Maps IP to {"channel_id": int, "device_id": str} for display purposes

# Frontend-like blueprint for display names
CHANNEL_DEVICES_BLUEPRINT_BACKEND = {
    'VS_M': {'name': 'VS M'},
    'VS_P': {'name': 'VS P'},
    'VS_B': {'name': 'VS B'},
    'CP_VS42M': {'name': '186-11 VS42M'},
    'CP_PGM42M': {'name': '402-11 PGM42M'},
    'DA_M': {'name': 'DA M'},
    'DA_P': {'name': 'DA P'},
    'DA_B': {'name': 'DA B'},
    'DA_M_OUT': {'name': 'DA M OUT'},
    'DA_B_OUT': {'name': 'DA B OUT'},
}

def load_configs():
    """Loads iLO configurations from JSON files."""
    global ILO_CREDENTIALS_MAP, CHANNEL_DEVICE_IP_MAP, GLOBAL_COLLECTIVE_IP_MAP, IP_TO_CHANNEL_DEVICE_LOOKUP

    ILO_CREDENTIALS_MAP = {}
    CHANNEL_DEVICE_IP_MAP = {}
    GLOBAL_COLLECTIVE_IP_MAP = {
        "VS_M": [],
        "VS_P": [],
        "VS_B": []
    }
    IP_TO_CHANNEL_DEVICE_LOOKUP = {}

    try:
        # Load channel iLO config
        if os.path.exists(CHANNEL_ILO_CONFIG_FILE):
            with open(CHANNEL_ILO_CONFIG_FILE, 'r') as f:
                channel_configs = json.load(f)
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
                            IP_TO_CHANNEL_DEVICE_LOOKUP[ip] = {"channel_id": channel_id, "device_id": device_id}
                            # Add to collective global map
                            if device_id in GLOBAL_COLLECTIVE_IP_MAP:
                                GLOBAL_COLLECTIVE_IP_MAP[device_id].append(ip)
                        else:
                            logging.warning(f"Skipping malformed device entry in channel {channel_id}: {device}")
        else:
            logging.warning(f"Channel iLO config file not found: {CHANNEL_ILO_CONFIG_FILE}")

        # Load global iLO config (for additional servers contributing to global blocks)
        if os.path.exists(GLOBAL_ILO_CONFIG_FILE):
            with open(GLOBAL_ILO_CONFIG_FILE, 'r') as f:
                global_configs = json.load(f)
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
                                GLOBAL_COLLECTIVE_IP_MAP[group_type].append(ip)
                                # Note: These global IPs might not have a channel_id, store only device_id/type
                                IP_TO_CHANNEL_DEVICE_LOOKUP[ip] = {"device_id": group_type}
                            else:
                                logging.warning(f"Skipping malformed additional IP entry for group {group_type}: {additional_ip_data}")
        else:
            logging.warning(f"Global iLO config file not found: {GLOBAL_ILO_CONFIG_FILE}")

        logging.info(f"Loaded {len(ILO_CREDENTIALS_MAP)} iLO credentials.")
        logging.debug(f"CHANNEL_DEVICE_IP_MAP: {CHANNEL_DEVICE_IP_MAP}")
        logging.debug(f"GLOBAL_COLLECTIVE_IP_MAP: {GLOBAL_COLLECTIVE_IP_MAP}")
        logging.debug(f"IP_TO_CHANNEL_DEVICE_LOOKUP: {IP_TO_CHANNEL_DEVICE_LOOKUP}")


    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON config file: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred while loading configs: {e}")

load_configs() # Load configs on startup

# --- Concurrency and Retry Configuration ---
MAX_RETRIES = 3
INITIAL_BACKOFF_SECONDS = 1
ILO_REQUEST_TIMEOUT_SECONDS = 15 # Timeout for each iLO Redfish API call

# Using a ThreadPoolExecutor for concurrent iLO requests.
# Increased max_workers to leverage more CPU/memory for faster polling.
# A value of 50-100 can be a good starting point for I/O-bound tasks like network requests
# with 150 total devices, but can be adjusted based on actual server resources and network latency.
executor = ThreadPoolExecutor(max_workers=50) 

def retry(max_retries, initial_backoff):
    """
    Decorator for retrying a function with exponential backoff.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except (requests.exceptions.RequestException, ValueError) as e:
                    logging.warning(f"Attempt {retries + 1}/{max_retries} failed for {func.__name__} ({args[0] if args else 'N/A'}): {e}")
                    retries += 1
                    if retries < max_retries:
                        sleep_time = initial_backoff * (2 ** (retries - 1)) + random.uniform(0, 0.5) # Add jitter
                        logging.info(f"Retrying ({args[0] if args else 'N/A'}) in {sleep_time:.2f} seconds...")
                        time.sleep(sleep_time)
            raise ConnectionError(f"Failed after {max_retries} attempts: {func.__name__} for {args[0] if args else 'N/A'}")
        return wrapper
    return decorator


# --- Helper functions ---

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

@retry(max_retries=MAX_RETRIES, initial_backoff=INITIAL_BACKOFF_SECONDS)
def get_active_iml_alarms(ilo_ip, username, password):
    """
    Fetches, filters, and dedupes active IML alarms for a given iLO.
    Returns a tuple: (highest_severity_status, list_of_active_alarms, error_message)
    Alarms are enriched with `channel_name` and `device_name` for frontend display.
    """
    IML_URL = f"https://{ilo_ip}/redfish/v1/Systems/1/LogServices/IML/Entries"
    active_alarms = []
    latest_entries_by_message = {} # Used for deduplication within a single iLO's logs
    highest_overall_priority = 0 # Corresponds to 'Informational' or lower

    logging.info(f"[{ilo_ip}] Attempting to fetch IML entries from {IML_URL}")

    # Determine display names for this IP
    display_info = IP_TO_CHANNEL_DEVICE_LOOKUP.get(ilo_ip, {})
    channel_id_for_display = display_info.get('channel_id')
    device_id_for_display = display_info.get('device_id')

    channel_name_for_alarm = f"Channel {str(channel_id_for_display).zfill(2)}" if channel_id_for_display else "Global"
    device_name_for_alarm = CHANNEL_DEVICES_BLUEPRINT_BACKEND.get(device_id_for_display, {}).get('name', device_id_for_display or 'N/A')


    session = requests.Session()
    session.auth = (username, password)
    session.verify = False  # IMPORTANT: Disable SSL verification for self-signed certificates (use with caution in prod!)
    session.timeout = ILO_REQUEST_TIMEOUT_SECONDS

    try:
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

            # Deduplicate by message, keeping the latest entry for THIS ILO
            # Note: Cross-iLO deduplication is handled on the frontend based on IP + message
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

            # Enrich the alarm with display names and add to the list
            active_alarms.append({
                "server_ip": ilo_ip,
                "message": message,
                "severity": severity,
                "timestamp": timestamp_str,
                "channel_name": channel_name_for_alarm, # Enriched for frontend
                "device_name": device_name_for_alarm   # Enriched for frontend
            })

            # Determine the highest priority among active alarms
            current_alarm_priority = get_alarm_severity_priority(severity)
            if current_alarm_priority > highest_overall_priority:
                highest_overall_priority = current_alarm_priority

    except requests.exceptions.Timeout:
        logging.error(f"[{ilo_ip}] Connection timed out while fetching IML logs.")
        return "unknown", [], f"Connection timed out to {ilo_ip}"
    except requests.exceptions.ConnectionError as e:
        logging.error(f"[{ilo_ip}] Connection error while fetching IML logs: {e}")
        return "unknown", [], f"Connection error to {ilo_ip}"
    except requests.exceptions.HTTPError as e:
        logging.error(f"[{ilo_ip}] HTTP error {e.response.status_code}: {e.response.reason} during IML fetch. Response: {e.response.text[:200]}...")
        return "unknown", [], f"HTTP error {e.response.status_code} from {ilo_ip}"
    except json.JSONDecodeError as e:
        logging.error(f"[{ilo_ip}] Failed to parse JSON response from IML: {e}")
        return "unknown", [], f"Invalid JSON response from {ilo_ip}"
    except Exception as e:
        logging.exception(f"[{ilo_ip}] An unexpected error occurred during IML collection.")
        return "unknown", [], f"Unexpected error during fetch from {ilo_ip}: {e}"
    finally:
        session.close()

    # Sort active alarms by timestamp descending
    active_alarms.sort(key=lambda x: datetime.strptime(x['timestamp'], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=pytz.UTC), reverse=True)

    # Map the highest priority found to the dashboard status
    overall_status_for_dashboard = map_severity_to_dashboard_status(
        next((s for s, p in [("Critical", 4), ("Warning", 3), ("Unknown", 2), ("OK", 1), ("Informational", 0)] if p == highest_overall_priority), "Unknown")
    )

    logging.info(f"[{ilo_ip}] Final IML status determined: {overall_status_for_dashboard} with {len(active_alarms)} active alarms.")
    return overall_status_for_dashboard, active_alarms, None # No error


# --- API Endpoints ---

@app.route('/get_ilo_status/<string:channel_id_str>/<string:device_id>', methods=['GET'])
def get_ilo_status(channel_id_str, device_id):
    """
    Flask endpoint to get the status and active alarms of a specific iLO server
    for a given channel and device (e.g., VS_M).
    This calls get_active_iml_alarms (which has retries and timeouts) and returns its data.
    """
    try:
        channel_id = int(channel_id_str)
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid channel_id", "alarms": []}), 400

    ip = CHANNEL_DEVICE_IP_MAP.get((channel_id, device_id))
    if not ip:
        logging.warning(f"IP not found for Channel {channel_id}, Device {device_id}. Returning unknown.")
        return jsonify({"status": "unknown", "message": "iLO IP not configured for this device/channel", "alarms": []})

    credentials = ILO_CREDENTIALS_MAP.get(ip)
    if not credentials:
        logging.error(f"Credentials not found for iLO IP: {ip}")
        return jsonify({"status": "error", "message": "iLO IP not configured or credentials missing", "alarms": []}), 404

    username = credentials['username']
    password = credentials['password']

    try:
        # Use the retry-enabled function to fetch status
        overall_status, active_alarms, error_msg = get_active_iml_alarms(ip, username, password)
        return jsonify({
            "ip": ip,
            "status": overall_status, # 'ok', 'warning', 'alarm', 'unknown'
            "alarms": active_alarms, # List of active alarms (already enriched)
            "error": error_msg
        })
    except ConnectionError as e:
        return jsonify({"status": "unknown", "alarms": [], "error": str(e)}), 500
    except Exception as e:
        logging.exception(f"An unexpected error occurred in /get_ilo_status for {ip}")
        return jsonify({"status": "unknown", "alarms": [], "error": f"Internal server error: {str(e)}"}), 500


@app.route('/get_collective_ilo_status/<string:block_type>', methods=['GET'])
def get_collective_ilo_status(block_type):
    """
    Flask endpoint to get the collective status and all active alarms
    for a group of iLO servers (e.g., all VS_M servers).
    Uses ThreadPoolExecutor for concurrent fetching.
    """
    ips_to_check = GLOBAL_COLLECTIVE_IP_MAP.get(block_type)

    if not ips_to_check:
        logging.warning(f"No IPs configured for collective block type: {block_type}. Returning unknown.")
        return jsonify({"status": "unknown", "message": "No IPs configured for this collective block type", "alarms": []})

    highest_overall_priority = 0
    all_collective_alarms = []
    has_errors = False
    error_details = []

    # Prepare futures for concurrent execution
    futures = []
    for ip in ips_to_check:
        credentials = ILO_CREDENTIALS_MAP.get(ip)
        if credentials:
            futures.append(executor.submit(get_active_iml_alarms, ip, credentials['username'], credentials['password']))
        else:
            logging.warning(f"Credentials not found for collective iLO IP: {ip}. Skipping for concurrent fetch.")
            has_errors = True
            error_details.append(f"Credentials missing for {ip}")


    for future in futures:
        try:
            current_status, current_alarms, error_msg = future.result() # Blocks until the future is done
            
            if error_msg:
                has_errors = True
                error_details.append(error_msg)

            # Aggregate alarms
            all_collective_alarms.extend(current_alarms)

            # Update highest overall priority
            current_priority = get_alarm_severity_priority(current_status)
            if current_priority > highest_overall_priority:
                highest_overall_priority = current_priority

        except ConnectionError as e: # This catches errors propagated from get_active_iml_alarms after retries
            logging.error(f"Error fetching for a collective device: {e}")
            has_errors = True
            error_details.append(str(e))
            # If any device fails, the collective status might degrade
            if highest_overall_priority < get_alarm_severity_priority("unknown"):
                highest_overall_priority = get_alarm_severity_priority("unknown")
        except Exception as e:
            logging.exception(f"An unexpected error occurred during collective fetch for {block_type}")
            has_errors = True
            error_details.append(f"Unexpected error: {str(e)}")
            if highest_overall_priority < get_alarm_severity_priority("unknown"):
                highest_overall_priority = get_alarm_severity_priority("unknown")


    # Sort all collected alarms by timestamp descending
    all_collective_alarms.sort(key=lambda x: datetime.strptime(x['timestamp'], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=pytz.UTC), reverse=True)

    collective_dashboard_status = map_severity_to_dashboard_status(
        next((s for s, p in [("Critical", 4), ("Warning", 3), ("Unknown", 2), ("OK", 1), ("Informational", 0)] if p == highest_overall_priority), "Unknown")
    )

    logging.info(f"Collective status for {block_type}: {collective_dashboard_status} with {len(all_collective_alarms)} alarms.")

    response_error = None
    if has_errors:
        response_error = "Errors occurred during fetching of some iLOs: " + "; ".join(error_details)

    return jsonify({
        "block_type": block_type,
        "status": collective_dashboard_status,
        "alarms": all_collective_alarms,
        "error": response_error
    })


if __name__ == '__main__':
    # Create dummy config files for testing if they don't exist
    if not os.path.exists(CHANNEL_ILO_CONFIG_FILE):
        logging.info(f"Creating dummy {CHANNEL_ILO_CONFIG_FILE}")
        dummy_channel_config = []
        for i in range(1, 51): # 50 channels
            channel_devices = []
            # VS_M, VS_P, VS_B
            channel_devices.append({"id": "VS_M", "ip": f"192.168.1.{i * 3 + 0}", "username": "admin", "password": "password"})
            channel_devices.append({"id": "VS_P", "ip": f"192.168.1.{i * 3 + 1}", "username": "admin", "password": "password"})
            channel_devices.append({"id": "VS_B", "ip": f"192.168.1.{i * 3 + 2}", "username": "admin", "password": "password"})
            dummy_channel_config.append({"channel_id": i, "devices": channel_devices})
        with open(CHANNEL_ILO_CONFIG_FILE, 'w') as f:
            json.dump(dummy_channel_config, f, indent=4)

    if not os.path.exists(GLOBAL_ILO_CONFIG_FILE):
        logging.info(f"Creating dummy {GLOBAL_ILO_CONFIG_FILE}")
        dummy_global_config = [
            {"type": "VS_M", "additional_ips": [{"ip": "192.168.2.1", "username": "admin", "password": "password"}]},
            {"type": "VS_P", "additional_ips": [{"ip": "192.168.2.2", "username": "admin", "password": "password"}]},
            {"type": "VS_B", "additional_ips": [{"ip": "192.168.2.3", "username": "admin", "password": "password"}]},
        ]
        with open(GLOBAL_ILO_CONFIG_FILE, 'w') as f:
            json.dump(dummy_global_config, f, indent=4)

    # Reload configs after dummy files might have been created
    load_configs()

    print(f"Backend proxy starting for approx. {len(ILO_CREDENTIALS_MAP)} iLO devices...")
    # For production deployment, use a WSGI server like Gunicorn (e.g., gunicorn -w 4 -t 60 app:app)
    # The `debug=False` setting is important for performance in production.
    app.run(host='0.0.0.0', port=5000, debug=False)
