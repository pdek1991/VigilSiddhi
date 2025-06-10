import requests
import logging
import urllib3
from datetime import datetime, timedelta
import pytz
import time
import random
import functools
from concurrent.futures import ThreadPoolExecutor

# Suppress insecure request warning for self-signed certificates (common with iLO)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging for better visibility and debugging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Retry Decorator ---
def retry(max_retries, initial_backoff):
    """
    A decorator for retrying a function with exponential backoff if it fails.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except (requests.exceptions.RequestException, ValueError) as e:
                    # Log the retry attempt
                    # args[0] is 'self', args[1] is the IP address in get_active_iml_alarms
                    ip_address = args[1] if len(args) > 1 else "N/A"
                    logging.warning(f"Attempt {retries + 1}/{max_retries} failed for {func.__name__} ({ip_address}): {e}")
                    retries += 1
                    if retries < max_retries:
                        # Exponential backoff with jitter
                        sleep_time = initial_backoff * (2 ** (retries - 1)) + random.uniform(0, 0.5)
                        logging.info(f"Retrying ({ip_address}) in {sleep_time:.2f} seconds...")
                        time.sleep(sleep_time)
            # Raise a specific error after all retries fail
            raise ConnectionError(f"Failed after {max_retries} attempts: {func.__name__} for {args[1] if len(args) > 1 else 'N/A'}")
        return wrapper
    return decorator


class ILOProxy:
    """
    A class to manage all interactions with HP iLO devices.
    It fetches its configuration from Elasticsearch and provides methods
    to get device status and alarms, which are then exposed via the API layer.
    """
    def __init__(self, es_client):
        """
        Initializes the ILOProxy service.
        :param es_client: An active Elasticsearch client instance.
        """
        self.es = es_client
        self.executor = ThreadPoolExecutor(max_workers=50) # For concurrent API calls
        self.ILO_CREDENTIALS_MAP = {}
        self.CHANNEL_DEVICE_IP_MAP = {}
        self.GLOBAL_COLLECTIVE_IP_MAP = {}
        self.IP_TO_CHANNEL_DEVICE_LOOKUP = {}
        
        # This is a static map for providing user-friendly names in alarms
        self.DEVICE_DISPLAY_NAMES = {
            'VS_M': 'VS M', 'VS_P': 'VS P', 'VS_B': 'VS B',
            'CP_VS42M': '186-11 VS42M', 'CP_PGM42M': '402-11 PGM42M',
            'DA_M': 'DA M', 'DA_P': 'DA P', 'DA_B': 'DA B',
            'DA_M_OUT': 'DA M OUT', 'DA_B_OUT': 'DA B OUT',
            'Encoder M': 'Encoder M', 'Encoder B': 'Encoder B',
            'Cisco D9800': 'Cisco D9800', 'Cisco Switch': 'Cisco Switch',
            'Nexus Switch': 'Nexus Switch', 'KMX': 'KMX',
        }

        # Load all configurations from Elasticsearch on startup
        self.load_configs()

    def load_configs(self):
        """
        Loads iLO configurations from the 'channel_config' and 'global_config'
        indices in Elasticsearch and populates the internal mapping dictionaries.
        """
        logging.info("Loading iLO configurations from Elasticsearch...")
        try:
            # 1. Load channel-specific iLO configurations
            res = self.es.search(index="channel_config", body={"query": {"match_all": {}}}, size=1000)
            for hit in res['hits']['hits']:
                channel_data = hit['_source']
                channel_id = channel_data.get('channel_id')
                if not channel_id:
                    continue
                for device in channel_data.get('devices', []):
                    ip = device.get('ip')
                    device_id = device.get('id')
                    if all([ip, device_id, device.get('username'), device.get('password')]):
                        self.ILO_CREDENTIALS_MAP[ip] = {"username": device['username'], "password": device['password']}
                        self.CHANNEL_DEVICE_IP_MAP[(channel_id, device_id)] = ip
                        self.IP_TO_CHANNEL_DEVICE_LOOKUP[ip] = {"channel_id": channel_id, "device_id": device_id}
                        # Also add to the global collective map for group lookups
                        if device_id not in self.GLOBAL_COLLECTIVE_IP_MAP:
                            self.GLOBAL_COLLECTIVE_IP_MAP[device_id] = []
                        self.GLOBAL_COLLECTIVE_IP_MAP[device_id].append(ip)

            # 2. Load global and collective configurations
            res = self.es.search(index="global_config", body={"query": {"match_all": {}}}, size=1000)
            for hit in res['hits']['hits']:
                group_data = hit['_source']
                group_type = group_data.get('type') # e.g., 'VS_M', 'Encoder M'
                if not group_type:
                    continue
                if group_type not in self.GLOBAL_COLLECTIVE_IP_MAP:
                    self.GLOBAL_COLLECTIVE_IP_MAP[group_type] = []
                for ip_info in group_data.get('additional_ips', []):
                    ip = ip_info.get('ip')
                    if all([ip, ip_info.get('username'), ip_info.get('password')]):
                        self.ILO_CREDENTIALS_MAP[ip] = {"username": ip_info['username'], "password": ip_info['password']}
                        self.GLOBAL_COLLECTIVE_IP_MAP[group_type].append(ip)
                        if ip not in self.IP_TO_CHANNEL_DEVICE_LOOKUP:
                            self.IP_TO_CHANNEL_DEVICE_LOOKUP[ip] = {"device_id": group_type, "group_id": group_data.get('id')}
            
            logging.info(f"Successfully loaded {len(self.ILO_CREDENTIALS_MAP)} total iLO device credentials.")
        except Exception as e:
            logging.error(f"FATAL: Failed to load iLO configurations from Elasticsearch. Service may not function. Error: {e}")

    # --- Helper Methods ---

    def _get_alarm_severity_priority(self, severity):
        severity_lower = str(severity).lower()
        if severity_lower == "critical": return 4
        if severity_lower == "warning": return 3
        if severity_lower == "ok": return 1
        if severity_lower == "informational": return 0
        return 2 # Default for 'Unknown' etc.

    def _map_severity_to_dashboard_status(self, severity):
        priority = self._get_alarm_severity_priority(severity)
        if priority == 4: return "alarm"
        if priority == 3: return "warning"
        if priority <= 1: return "ok"
        return "unknown"

    def _is_entry_active(self, entry):
        return not entry.get("Oem", {}).get("Hpe", {}).get("Repaired", True)

    def _is_within_last_x_days(self, timestamp, days=30):
        try:
            log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=pytz.UTC)
            return log_time >= datetime.utcnow().replace(tzinfo=pytz.UTC) - timedelta(days=days)
        except (ValueError, TypeError):
            return False

    # --- Core Logic ---

    @retry(max_retries=3, initial_backoff=1)
    def get_active_iml_alarms(self, ilo_ip, username, password):
        """
        Fetches, filters, and dedupes active IML alarms for a single iLO device.
        This is the core worker function called by the API-facing methods.
        Returns a tuple: (highest_severity_status, list_of_active_alarms, error_message)
        """
        IML_URL = f"https://{ilo_ip}/redfish/v1/Systems/1/LogServices/IML/Entries"
        active_alarms = []
        highest_overall_priority = 0

        # Get display names for enriching alarm messages
        display_info = self.IP_TO_CHANNEL_DEVICE_LOOKUP.get(ilo_ip, {})
        channel_id = display_info.get('channel_id')
        device_id = display_info.get('device_id')
        channel_name_for_alarm = f"Channel {str(channel_id).zfill(2)}" if channel_id else "Global"
        device_name_for_alarm = self.DEVICE_DISPLAY_NAMES.get(device_id, device_id or 'N/A')
        
        session = requests.Session()
        session.auth = (username, password)
        session.verify = False # Disable SSL verification
        session.timeout = 15 # Seconds

        try:
            response = session.get(IML_URL)
            response.raise_for_status()
            entries = response.json().get("Members", [])

            latest_entries = {}
            for entry in entries:
                if self._is_within_last_x_days(entry.get("Created")) and self._is_entry_active(entry):
                    message = entry.get("Message", "No message")
                    # Deduplicate by message, keeping only the most recent one
                    if message not in latest_entries or entry.get("Created") > latest_entries[message].get("Created"):
                        latest_entries[message] = entry
            
            for entry in latest_entries.values():
                severity = entry.get("Severity", "Unknown")
                current_priority = self._get_alarm_severity_priority(severity)
                if current_priority > highest_overall_priority:
                    highest_overall_priority = current_priority
                
                active_alarms.append({
                    "server_ip": ilo_ip,
                    "message": entry.get("Message", "No message"),
                    "severity": severity,
                    "timestamp": entry.get("Created"),
                    "channel_name": channel_name_for_alarm,
                    "device_name": device_name_for_alarm
                })

        except requests.exceptions.RequestException as e:
            logging.error(f"[{ilo_ip}] Network/HTTP error: {e}")
            # Generate a synthetic alarm for the connection failure
            status, alarm = "alarm", {
                "server_ip": ilo_ip, "message": f"Connection failed: {e}", "severity": "CRITICAL", 
                "timestamp": datetime.now().isoformat(), "channel_name": channel_name_for_alarm, "device_name": device_name_for_alarm
            }
            return status, [alarm], str(e)
        except json.JSONDecodeError as e:
            logging.error(f"[{ilo_ip}] JSON parsing error: {e}")
            status, alarm = "alarm", {
                "server_ip": ilo_ip, "message": "Failed to parse Redfish API response.", "severity": "CRITICAL", 
                "timestamp": datetime.now().isoformat(), "channel_name": channel_name_for_alarm, "device_name": device_name_for_alarm
            }
            return status, [alarm], "Invalid JSON response from device."
        finally:
            session.close()

        # Sort alarms by time, newest first
        active_alarms.sort(key=lambda x: x['timestamp'], reverse=True)
        
        status_map = {4: "alarm", 3: "warning", 2: "unknown", 1: "ok", 0: "ok"}
        overall_status = status_map.get(highest_overall_priority, "ok")
        
        return overall_status, active_alarms, None

    # --- Public Methods (called by API layer) ---

    def get_status_for_single_device(self, channel_id_str, device_id):
        """
        Handles API requests for a single iLO device's status.
        """
        try:
            channel_id = int(channel_id_str)
        except ValueError:
            return {"status": "error", "message": "Invalid channel_id format", "alarms": []}, 400

        ip = self.CHANNEL_DEVICE_IP_MAP.get((channel_id, device_id))
        if not ip:
            return {"status": "unknown", "message": "iLO IP not configured", "alarms": []}, 404

        credentials = self.ILO_CREDENTIALS_MAP.get(ip)
        if not credentials:
            return {"status": "error", "message": "Credentials not configured", "alarms": []}, 404

        try:
            status, alarms, error = self.get_active_iml_alarms(ip, credentials['username'], credentials['password'])
            return {"ip": ip, "status": status, "alarms": alarms, "error": error}, 200
        except ConnectionError as e:
            return {"status": "alarm", "alarms": [], "error": str(e)}, 503
        except Exception as e:
            logging.exception(f"Unexpected error in get_status_for_single_device for {ip}")
            return {"status": "unknown", "alarms": [], "error": "Internal server error"}, 500

    def get_status_for_collective(self, block_type):
        """
        Handles API requests for a collective group of devices (e.g., all 'VS_M').
        Uses a thread pool to fetch data concurrently.
        """
        ips_to_check = self.GLOBAL_COLLECTIVE_IP_MAP.get(block_type, [])
        if not ips_to_check:
            return {"status": "unknown", "message": f"No IPs configured for type '{block_type}'", "alarms": []}, 404

        highest_overall_priority = 0
        all_collective_alarms = []
        errors = []
        
        futures = {self.executor.submit(self.get_active_iml_alarms, ip, self.ILO_CREDENTIALS_MAP[ip]['username'], self.ILO_CREDENTIALS_MAP[ip]['password']): ip 
                   for ip in ips_to_check if ip in self.ILO_CREDENTIALS_MAP}

        for future in futures:
            ip = futures[future]
            try:
                status, alarms, error = future.result()
                if error:
                    errors.append(f"{ip}: {error}")
                all_collective_alarms.extend(alarms)
                current_priority = self._get_alarm_severity_priority(status)
                if current_priority > highest_overall_priority:
                    highest_overall_priority = current_priority
            except Exception as e:
                logging.error(f"Error fetching collective status for {ip} of type {block_type}: {e}")
                errors.append(f"{ip}: {e}")
                # If any device in the group fails completely, the group status is critical
                if highest_overall_priority < self._get_alarm_severity_priority("critical"):
                    highest_overall_priority = self._get_alarm_severity_priority("critical")

        status_map = {4: "alarm", 3: "warning", 2: "unknown", 1: "ok", 0: "ok"}
        collective_status = status_map.get(highest_overall_priority, "ok")
        
        # If there were errors but no critical alarms, elevate status to warning
        if errors and collective_status == "ok":
            collective_status = "warning"
            
        all_collective_alarms.sort(key=lambda x: x['timestamp'], reverse=True)
        
        response_error = "; ".join(errors) if errors else None

        return {
            "block_type": block_type,
            "status": collective_status,
            "alarms": all_collective_alarms,
            "error": response_error
        }, 200
