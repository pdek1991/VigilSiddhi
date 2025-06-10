import requests
import xml.etree.ElementTree as ET
import json
import logging
from datetime import datetime
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class D9800IRD:
    """
    Monitors Cisco D9800 IRD devices by fetching status data, parsing it,
    and storing relevant information and alarms in Elasticsearch.
    """
    # Configuration
    USERNAME = "admin"
    PASSWORD = "localadmin"
    HEADERS = {'Content-Type': 'text/xml; charset=UTF-8'}
    VERIFY_SSL = False  # Set to True in production with proper SSL certificates

    def __init__(self, es_client):
        """
        Initializes the D9800IRD monitor with an Elasticsearch client.

        Args:
            es_client: An instance of the Elasticsearch client.
        """
        self.es = es_client
        self.configs = self._load_config()
        self.session_ids = {} # Cache for session IDs: {ip: session_id}

    def _load_config(self):
        """
        Loads IRD configurations from Elasticsearch.
        The configuration is expected to be in an index named "ird_config".
        Each document in "ird_config" should contain at least an 'ip_address' field,
        and optionally 'username' and 'password' if they differ from defaults.
        """
        configs = []
        try:
            # Fetch all documents from the 'ird_config' index
            res = self.es.search(index="ird_config", body={"query": {"match_all": {}}}, size=1000)
            for hit in res['hits']['hits']:
                # Append the source document of each hit
                configs.append(hit['_source'])
            logging.info(f"Loaded {len(configs)} D9800 IRD configurations from Elasticsearch.")
            return configs
        except Exception as e:
            logging.error(f"Failed to load IRD configs from Elasticsearch: {e}")
            return []

    def _create_session(self, ip_address, username, password):
        """
        Logs in to the device API at the given IP and retrieves a session ID.
        The login endpoint returns XML, which is parsed to extract the SESSION_ID.

        Args:
            ip_address (str): The IP address of the IRD device.
            username (str): The username for API login.
            password (str): The password for API login.

        Returns:
            str: The session ID if login is successful, None otherwise.
        """
        LOGIN_URL = f"https://{ip_address}/ws/v1/table?t=return"
        payload = f"""
        <HDR><LOGIN>
        <UID>{username}</UID>
        <USERPASS>{password}</USERPASS>
        </LOGIN></HDR>
        """
        try:
            # Send POST request for login
            response = requests.post(LOGIN_URL, data=payload.strip(), headers=self.HEADERS, verify=self.VERIFY_SSL, timeout=10)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

            # Parse the XML response
            xml_root = ET.fromstring(response.text)
            session_id_elem = xml_root.find('.//SESSION_ID')
            if session_id_elem is not None:
                logging.info(f"Session created successfully for {ip_address}")
                return session_id_elem.text
            else:
                logging.error(f"SESSION_ID not found in login response for {ip_address}.")
                return None
        except requests.exceptions.RequestException as e:
            logging.error(f"HTTP Error during login for {ip_address}: {e}")
            return None
        except ET.ParseError as e:
            logging.error(f"XML Parse Error during login for {ip_address}: {e}")
            return None
        except Exception as e:
            logging.error(f"An unexpected error occurred during login for {ip_address}: {e}")
            return None

    def _fetch_data(self, ip_address, session_id, endpoint, json_output=False):
        """
        Fetches data from a specified API endpoint for the given IP address.
        It can request XML or JSON data based on the `json_output` flag.
        Includes a fallback to XML parsing if JSON is requested but XML is returned.

        Args:
            ip_address (str): The IP address of the IRD device.
            session_id (str): The active session ID.
            endpoint (str): The API endpoint to fetch data from (e.g., "input/rf").
            json_output (bool): If True, appends "?js=1" to the URL to request JSON.

        Returns:
            dict or xml.etree.ElementTree.Element: Parsed JSON or XML data, or None on error.
        """
        BASE_URL = f"https://{ip_address}/ws/v2/status"
        url = f"{BASE_URL}/{endpoint}"
        if json_output:
            url += "?js=1" # Append ?js=1 for JSON output as per API documentation
        
        headers = {"X-SESSION-ID": session_id}
        try:
            response = requests.get(url, headers=headers, verify=self.VERIFY_SSL, timeout=15)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            
            if json_output:
                try:
                    return response.json()
                except json.JSONDecodeError:
                    logging.warning(f"Expected JSON for {endpoint} at {ip_address}, but received XML. Attempting XML parse.")
                    return ET.fromstring(response.text) # Fallback to XML parsing
            else:
                return ET.fromstring(response.text) # Return XML if not explicitly requesting JSON
        except requests.exceptions.RequestException as e:
            logging.error(f"HTTP Error fetching {endpoint} for {ip_address} ({'JSON' if json_output else 'XML'}): {e}")
            return None
        except (json.JSONDecodeError, ET.ParseError) as e:
            # This catch will now only trigger if the initial parse failed for the expected type
            logging.error(f"Content Parse Error fetching {endpoint} for {ip_address}: {e}")
            return None
        except Exception as e:
            logging.error(f"An unexpected error occurred fetching {endpoint} for {ip_address}: {e}")
            return None

    def _parse_rf_input_stats(self, data, ip_address):
        """
        Parses RF input statistics, showing only locked ports and specific keys.
        Expects JSON data.

        Args:
            data (dict): The JSON data from the RF input endpoint.
            ip_address (str): The IP address of the IRD device.

        Returns:
            list: A list of dictionaries, each representing a locked RF input port.
        """
        parsed_results = []
        if not data or 'input' not in data or 'rf' not in data['input']:
            logging.warning(f"No RF input data available or unexpected structure for {ip_address}.")
            return parsed_results

        rf_entries = data['input']['rf']
        if not isinstance(rf_entries, list):
            rf_entries = [rf_entries] # Ensure it's a list for consistent iteration

        for rf in rf_entries:
            satlock_status = rf.get("satlock", "N/A")
            if satlock_status.lower() == "lock+sig":
                parsed_results.append({
                    "card": rf.get("card", "N/A"),
                    "port": rf.get("port", "N/A"),
                    "satlock": satlock_status,
                    "inputrate": rf.get("inputrate", "N/A"),
                    "pol": rf.get("pol", "N/A"),
                    "symrate": rf.get("symrate", "N/A"),
                    "fec": rf.get("fec", "N/A"),
                    "siglevel": rf.get("siglevel", "N/A"),
                    "cnmargin": rf.get("cnmargin", "N/A")
                })
        return parsed_results

    def _parse_moip_status(self, data, ip_address):
        """
        Parses MOIP input status, displaying only active or locked ports.
        Expects JSON data.

        Args:
            data (dict): The JSON data from the MOIP endpoint.
            ip_address (str): The IP address of the IRD device.

        Returns:
            list: A list of dictionaries, each representing an active/locked MOIP port.
        """
        parsed_results = []
        if not data or 'input' not in data or 'moip' not in data['input']:
            logging.warning(f"No MOIP data available or unexpected structure for {ip_address}.")
            return parsed_results

        moip_entries = data['input']['moip']
        if not isinstance(moip_entries, list):
            moip_entries = [moip_entries]

        for moip in moip_entries:
            moiplock = moip.get("moiplock", "N/A")
            act = moip.get("act", "N/A")

            if act.lower() == "active" or moiplock.lower() != "no lock":
                parsed_results.append({
                    "card": moip.get("card", "N/A"),
                    "port": moip.get("port", "N/A"),
                    "moiplock": moiplock,
                    "activity": act,
                    "input_id": moip.get("inputid", "N/A"),
                    "data_source_1": moip.get("datasrc1", "N/A"),
                    "dr_state": moip.get("drstate", "N/A")
                })
        return parsed_results

    def _parse_channel_status(self, data, ip_address):
        """
        Parses channel status, displaying only active channels.
        Expects JSON data.

        Args:
            data (dict): The JSON data from the PE (Program Element) endpoint.
            ip_address (str): The IP address of the IRD device.

        Returns:
            list: A list of dictionaries, each representing an active channel.
        """
        parsed_results = []
        if not data or 'pe' not in data or 'record' not in data['pe']:
            logging.warning(f"No channel data available or unexpected structure for {ip_address}.")
            return parsed_results

        channel_records = data['pe']['record']
        if not isinstance(channel_records, list):
            channel_records = [channel_records]

        for record in channel_records:
            prgmstatus = record.get("prgmstatus", "N/A")
            if prgmstatus.lower() == "active":
                parsed_results.append({
                    "pe_id": record.get("peid", "N/A"),
                    "channel_name": record.get("chname", "N/A"),
                    "input": record.get("inp", "N/A"),
                    "program_status": prgmstatus,
                    "ca_auth": record.get("caauth", "N/A"),
                    "hd_licensed": record.get("hdlicensed", "N/A")
                })
        return parsed_results

    def _parse_hardware_status(self, data, ip_address):
        """
        Parses hardware status, displaying only components that are NOT 'Ok'.
        Expects JSON data.

        Args:
            data (dict): The JSON data from the device/power endpoint.
            ip_address (str): The IP address of the IRD device.

        Returns:
            list: A list of dictionaries, each representing a hardware component with issues.
        """
        parsed_results = []
        if not data or 'device' not in data or 'power' not in data['device']:
            logging.warning(f"No hardware data available or unexpected structure for {ip_address}.")
            return parsed_results
        
        power_entries = data['device']['power']
        if not isinstance(power_entries, list):
            power_entries = [power_entries]

        for power in power_entries:
            status = power.get("status", "N/A")
            if status.lower() != "ok":
                parsed_results.append({
                    "slot": power.get("slot", "N/A"),
                    "board_name": power.get("displayBoardName", "N/A"),
                    "good_status": power.get("good", "N/A"),
                    "overall_status": status
                })
        return parsed_results

    def _parse_eth_status(self, data, ip_address):
        """
        Parses Ethernet status, identifying 'Link Down' alarms for specific IP ranges.
        Only displays entries where the IP is within the specified ranges.
        Expects JSON data.

        Args:
            data (dict): The JSON data from the device/eth endpoint.
            ip_address (str): The IP address of the IRD device.

        Returns:
            list: A list of dictionaries, each representing an Ethernet port with relevant status.
        """
        parsed_results = []
        if not data or 'device' not in data or 'eth' not in data['device']:
            logging.warning(f"No Ethernet data available or unexpected structure for {ip_address}.")
            return parsed_results

        eth_entries = data['device']['eth']
        if not isinstance(eth_entries, list):
            eth_entries = [eth_entries]

        for eth in eth_entries:
            port = eth.get("port", "N/A")
            name = eth.get("name", "N/A")
            link = eth.get("link", "N/A")
            ipv4addr = eth.get("ipv4addr", "N/A")
            alarm = "No"

            is_relevant_ip = False
            # Check for 172.19.206.1 to 172.19.206.45
            if ipv4addr.startswith("172.19.206."):
                parts = ipv4addr.split('.')
                if len(parts) == 4 and parts[3].isdigit():
                    last_octet = int(parts[3])
                    if 1 <= last_octet <= 45: # Adjusted to 45 as per the main loop in get_d9800ird.py
                        is_relevant_ip = True
            # Check for 10.10.x.x series
            elif ipv4addr.startswith("10.10."):
                is_relevant_ip = True
            
            # Only process and display if the IP is relevant
            if is_relevant_ip:
                if link.lower() == "link down":
                    alarm = "YES (Port Down in Critical IP Range)"
                parsed_results.append({
                    "port": port,
                    "name": name,
                    "link_status": link,
                    "ipv4_address": ipv4addr,
                    "alarm": alarm
                })
        return parsed_results

    def _parse_active_faults(self, data, ip_address):
        """
        Parses active faults, showing only 'Major' or 'Critical' severity.
        Expects JSON data.

        Args:
            data (dict): The JSON data from the faults endpoint.
            ip_address (str): The IP address of the IRD device.

        Returns:
            list: A list of dictionaries, each representing a major/critical fault.
        """
        parsed_results = []
        if not data or 'faults' not in data or 'status' not in data['faults']:
            logging.warning(f"No fault data available or unexpected structure for {ip_address}.")
            return parsed_results

        status_entries = data['faults']['status']
        if not isinstance(status_entries, list):
            status_entries = [status_entries]

        for status in status_entries:
            severity = status.get("severity", "N/A")
            trapstate = status.get("trapstate", "N/A")

            if trapstate.lower() == "set" and (severity.lower() == "major" or severity.lower() == "critical"):
                parsed_results.append({
                    "name": status.get("name", "N/A"),
                    "type": status.get("type", "N/A"),
                    "severity": severity,
                    "details": status.get("details", "N/A"),
                    "set_since": status.get("setsince", "N/A")
                })
        return parsed_results

    def get_all_statuses(self):
        """
        Fetches status from all configured IRDs, parses the data,
        generates alarms, and stores trend and alarm data in Elasticsearch.

        Returns:
            dict: A dictionary containing 'status_data' (list of dictionaries for each IRD)
                  and 'alarms' (list of dictionaries for all generated alarms).
        """
        all_results = []
        all_alarms = []

        for config in self.configs:
            ip = config.get('ip_address')
            username = config.get('username', self.USERNAME)
            password = config.get('password', self.PASSWORD)

            if not ip:
                logging.warning("Skipping configuration with missing IP address.")
                continue

            ird_status = {"ip_address": ip}
            current_alarms = [] # Alarms for the current IRD

            logging.info(f"\nProcessing IRD: {ip}")

            session_id = None
            try:
                session_id = self._create_session(ip, username, password)
                if not session_id:
                    logging.error(f"Skipping data fetching for {ip}: Could not establish a session.")
                    ird_status["error"] = "Could not establish session"
                    all_results.append(ird_status)
                    continue

                # Fetch and parse RF Input Stats
                rf_data = self._fetch_data(ip, session_id, "input/rf", json_output=True)
                if rf_data:
                    parsed_rf = self._parse_rf_input_stats(rf_data, ip)
                    ird_status["rf_input_stats"] = parsed_rf
                    for entry in parsed_rf:
                        if entry.get("satlock", "").lower() != "lock+sig":
                            current_alarms.append({
                                "ip_address": ip,
                                "type": "RF Input Alarm",
                                "severity": "Major",
                                "description": f"RF card {entry.get('card', 'N/A')}, port {entry.get('port', 'N/A')} is not locked (Status: {entry.get('satlock', 'N/A')})",
                                "timestamp": datetime.now().isoformat()
                            })

                # Fetch and parse MOIP Status
                moip_data = self._fetch_data(ip, session_id, "input/moip", json_output=True)
                if moip_data:
                    parsed_moip = self._parse_moip_status(moip_data, ip)
                    ird_status["moip_status"] = parsed_moip
                    for entry in parsed_moip:
                        if entry.get("moiplock", "").lower() == "no lock" or entry.get("activity", "").lower() != "active":
                            current_alarms.append({
                                "ip_address": ip,
                                "type": "MOIP Status Alarm",
                                "severity": "Major",
                                "description": f"MOIP card {entry.get('card', 'N/A')}, port {entry.get('port', 'N/A')} is not active or locked (Lock: {entry.get('moiplock', 'N/A')}, Activity: {entry.get('activity', 'N/A')})",
                                "timestamp": datetime.now().isoformat()
                            })

                # Fetch and parse Channel Status
                channel_data = self._fetch_data(ip, session_id, "pe", json_output=True)
                if channel_data:
                    parsed_channels = self._parse_channel_status(channel_data, ip)
                    ird_status["channel_status"] = parsed_channels
                    for entry in parsed_channels:
                        if entry.get("program_status", "").lower() != "active":
                            current_alarms.append({
                                "ip_address": ip,
                                "type": "Channel Status Alarm",
                                "severity": "Minor",
                                "description": f"Channel '{entry.get('channel_name', 'N/A')}' (PE ID: {entry.get('pe_id', 'N/A')}) is not active (Status: {entry.get('program_status', 'N/A')})",
                                "timestamp": datetime.now().isoformat()
                            })

                # Fetch and parse Hardware Status
                power_data = self._fetch_data(ip, session_id, "device/power", json_output=True)
                if power_data:
                    parsed_hardware = self._parse_hardware_status(power_data, ip)
                    ird_status["hardware_status"] = parsed_hardware
                    for entry in parsed_hardware:
                        if entry.get("overall_status", "").lower() != "ok":
                            current_alarms.append({
                                "ip_address": ip,
                                "type": "Hardware Fault",
                                "severity": "Critical",
                                "description": f"Hardware component '{entry.get('board_name', 'N/A')}' in slot {entry.get('slot', 'N/A')} has status: {entry.get('overall_status', 'N/A')}",
                                "timestamp": datetime.now().isoformat()
                            })

                # Fetch and parse Ethernet Status
                eth_data = self._fetch_data(ip, session_id, "device/eth", json_output=True)
                if eth_data:
                    parsed_eth = self._parse_eth_status(eth_data, ip)
                    ird_status["ethernet_status"] = parsed_eth
                    for entry in parsed_eth:
                        if entry.get("alarm") == "YES (Port Down in Critical IP Range)":
                            current_alarms.append({
                                "ip_address": ip,
                                "type": "Ethernet Link Down Alarm",
                                "severity": "Critical",
                                "description": f"Ethernet port '{entry.get('name', 'N/A')}' ({entry.get('ipv4_address', 'N/A')}) is Link Down.",
                                "timestamp": datetime.now().isoformat()
                            })

                # Fetch and parse Active Faults
                faults_data = self._fetch_data(ip, session_id, "faults", json_output=True)
                if faults_data:
                    parsed_faults = self._parse_active_faults(faults_data, ip)
                    ird_status["active_faults"] = parsed_faults
                    for fault in parsed_faults:
                        all_alarms.append({
                            "ip_address": ip,
                            "type": "Active Fault",
                            "severity": fault.get("severity", "N/A"),
                            "name": fault.get("name", "N/A"),
                            "description": fault.get("details", "N/A"),
                            "set_since": fault.get("set_since", "N/A"),
                            "timestamp": datetime.now().isoformat()
                        })
            
            except Exception as e:
                logging.error(f"An unhandled error occurred while processing {ip}: {e}")
                ird_status["error"] = f"Unhandled error: {e}"
                
            all_results.append(ird_status)
            all_alarms.extend(current_alarms) # Add alarms specific to this IRD

            # Store trend data (all parsed data for the current IRD)
            try:
                trend_doc = {
                    "timestamp": datetime.now().isoformat(),
                    "ip_address": ip,
                    "data": ird_status # Store all collected data for this IRD
                }
                self.es.index(index="ird_trend", document=trend_doc)
                logging.info(f"Trend data for {ip} written to Elasticsearch 'ird_trend' index.")
            except Exception as e:
                logging.error(f"Failed to write trend data for {ip} to Elasticsearch: {e}")

            # Store generated alarms in active_alarms and historical_alarms indices
            for alarm in current_alarms:
                try:
                    self.es.index(index="active_alarms", document=alarm)
                    self.es.index(index="historical_alarms", document=alarm)
                    logging.info(f"Alarm for {ip} (Severity: {alarm.get('severity', 'N/A')}) written to Elasticsearch.")
                except Exception as e:
                    logging.error(f"Failed to write alarm for {ip} to Elasticsearch: {e}")

        return {"status_data": all_results, "alarms": all_alarms}