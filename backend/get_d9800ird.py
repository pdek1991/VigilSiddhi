import requests
import xml.etree.ElementTree as ET
from prettytable import PrettyTable
import json
import re

# ------------------ Configuration ------------------ #
# D9800_IP is now set dynamically within the main function loop
USERNAME = "admin"
PASSWORD = "localadmin"
# BASE_URL and LOGIN_URL will be constructed inside main for each IP

HEADERS = {'Content-Type': 'text/xml; charset=UTF-8'}
# IMPORTANT: For production environments, always use proper SSL certificate verification.
# Set VERIFY_SSL to True and ensure you have the correct certificates configured.
VERIFY_SSL = False  # Set to True if trusted certificate

# ------------------ Login Function ------------------ #
def create_session(ip_address):
    """
    Logs in to the device API at the given IP and retrieves a session ID.
    The login endpoint returns XML, so it's parsed accordingly.
    """
    LOGIN_URL = f"https://{ip_address}/ws/v1/table?t=return"
    payload = f"""
    <HDR><LOGIN>
    <UID>{USERNAME}</UID>
    <USERPASS>{PASSWORD}</USERPASS>
    </LOGIN></HDR>
    """
    try:
        response = requests.post(LOGIN_URL, data=payload.strip(), headers=HEADERS, verify=VERIFY_SSL, timeout=10)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        xml_root = ET.fromstring(response.text)
        session_id_elem = xml_root.find('.//SESSION_ID')
        if session_id_elem is not None:
            return session_id_elem.text
        else:
            print(f"[!] Error for {ip_address}: SESSION_ID not found in login response.")
            return None
    except requests.exceptions.RequestException as e:
        print(f"[!] HTTP Error during login for {ip_address}: {e}")
        return None
    except ET.ParseError as e:
        print(f"[!] XML Parse Error during login for {ip_address}: {e}")
        return None
    except Exception as e:
        print(f"[!] An unexpected error occurred during login for {ip_address}: {e}")
        return None

# ------------------ Fetch Data from Endpoint ------------------ #
def fetch_data(ip_address, session_id, endpoint, json_output=False):
    """
    Fetches data from a specified API endpoint for the given IP address.
    Can request XML or JSON data based on `json_output` flag.
    """
    BASE_URL = f"https://{ip_address}/ws/v2/status"
    url = f"{BASE_URL}/{endpoint}"
    if json_output:
        url += "?js=1" # Append ?js=1 for JSON output as requested
    
    headers = {"X-SESSION-ID": session_id}
    try:
        response = requests.get(url, headers=headers, verify=VERIFY_SSL, timeout=15)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        
        if json_output:
            return response.json()
        else:
            # If JSON output is requested but we get XML (e.g., endpoint doesn't support ?js=1)
            # This is a fallback for robustness, but ideally, the API should return JSON.
            try:
                # Attempt to parse as JSON first, if it fails, then try XML
                return response.json() 
            except json.JSONDecodeError:
                return ET.fromstring(response.text)
    except requests.exceptions.RequestException as e:
        print(f"[!] HTTP Error fetching {endpoint} for {ip_address} ({'JSON' if json_output else 'XML'}): {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"[!] JSON Decode Error fetching {endpoint} for {ip_address}: {e}")
        return None
    except ET.ParseError as e:
        print(f"[!] XML Parse Error fetching {endpoint} for {ip_address}: {e}")
        return None
    except Exception as e:
        print(f"[!] An unexpected error occurred fetching {endpoint} for {ip_address}: {e}")
        return None

# ------------------ Parsers with Filtering ------------------ #

def parse_rf_input_stats(data, ip_address):
    """
    Parses RF input statistics, showing only locked ports and specific keys.
    Expects JSON data.
    Keys: card, port, satlock, pol, symrate, fec, siglevel, cnmargin, inputrate.
    """
    print(f"\n--- [ RF INPUT STATS for {ip_address} (Locked Ports Only) ] ---")
    table = PrettyTable(["Card", "Port", "Satlock", "Input Rate", "Pol", "Symrate", "FEC", "Siglevel", "CN Margin"])
    table.align = "l"

    if not data or 'input' not in data or 'rf' not in data['input']:
        print("No RF input data available or data structure is unexpected.")
        return

    rf_entries = data['input']['rf']
    if not isinstance(rf_entries, list):
        rf_entries = [rf_entries]

    for rf in rf_entries:
        satlock_status = rf.get("satlock", "N/A")
        
        if satlock_status.lower() == "lock+sig":
            card = rf.get("card", "N/A")
            port = rf.get("port", "N/A")
            input_rate = rf.get("inputrate", "N/A")
            pol = rf.get("pol", "N/A")
            symrate = rf.get("symrate", "N/A")
            fec = rf.get("fec", "N/A")
            siglevel = rf.get("siglevel", "N/A")
            cnmargin = rf.get("cnmargin", "N/A")
            
            table.add_row([card, port, satlock_status, input_rate, pol, symrate, fec, siglevel, cnmargin])
    
    if not table._rows:
        print("No locked RF input ports found.")
    print(table)


def parse_moip_status(data, ip_address):
    """
    Parses MOIP input status, displaying only active or locked ports.
    Expects JSON data.
    """
    print(f"\n--- [ MOIP PORT STATUS for {ip_address} (Active or Locked Ports Only) ] ---")
    table = PrettyTable(["Card", "Port", "MOIP Lock", "Activity", "Input ID", "Data Source 1", "DR State"])
    table.align = "l"

    if not data or 'input' not in data or 'moip' not in data['input']:
        print("No MOIP data available or data structure is unexpected.")
        return

    moip_entries = data['input']['moip']
    if not isinstance(moip_entries, list):
        moip_entries = [moip_entries]

    for moip in moip_entries:
        moiplock = moip.get("moiplock", "N/A")
        act = moip.get("act", "N/A")

        if act.lower() == "active" or moiplock.lower() != "no lock":
            card = moip.get("card", "N/A")
            port = moip.get("port", "N/A")
            input_id = moip.get("inputid", "N/A")
            datasrc1 = moip.get("datasrc1", "N/A")
            drstate = moip.get("drstate", "N/A")
            table.add_row([card, port, moiplock, act, input_id, datasrc1, drstate])
    
    if not table._rows:
        print("No active or locked MOIP ports found.")
    print(table)


def parse_channel_status(data, ip_address):
    """
    Parses channel status, displaying only active channels.
    Expects JSON data.
    """
    print(f"\n--- [ CHANNEL STATUS for {ip_address} (Active Channels Only) ] ---")
    table = PrettyTable(["PE ID", "Channel Name", "Input", "Program Status", "CA Auth", "HD Licensed"])
    table.align = "l"

    if not data or 'pe' not in data or 'record' not in data['pe']:
        print("No channel data available or data structure is unexpected.")
        return

    channel_records = data['pe']['record']
    if not isinstance(channel_records, list):
        channel_records = [channel_records]

    for record in channel_records:
        prgmstatus = record.get("prgmstatus", "N/A")
        if prgmstatus.lower() == "active":
            peid = record.get("peid", "N/A")
            chname = record.get("chname", "N/A")
            inp = record.get("inp", "N/A")
            caauth = record.get("caauth", "N/A")
            hdlicensed = record.get("hdlicensed", "N/A")
            table.add_row([peid, chname, inp, prgmstatus, caauth, hdlicensed])
    
    if not table._rows:
        print("No active channels found.")
    print(table)


def parse_hardware_status(data, ip_address):
    """
    Parses hardware status, displaying only components that are NOT 'Ok'.
    Expects JSON data.
    """
    print(f"\n--- [ HARDWARE STATUS for {ip_address} (Issues Only) ] ---")
    table = PrettyTable(["Slot", "Board Name", "Good Status", "Overall Status"])
    table.align = "l"

    if not data or 'device' not in data or 'power' not in data['device']:
        print("No hardware data available or data structure is unexpected.")
        return
    
    power_entries = data['device']['power']
    if not isinstance(power_entries, list):
        power_entries = [power_entries]

    for power in power_entries:
        status = power.get("status", "N/A")
        if status.lower() != "ok":
            slot = power.get("slot", "N/A")
            display_board_name = power.get("displayBoardName", "N/A")
            good_status = power.get("good", "N/A")
            table.add_row([slot, display_board_name, good_status, status])
    
    if not table._rows:
        print("All hardware components are reported as 'Ok'.")
    print(table)


def parse_eth_status(data, ip_address):
    """
    Parses Ethernet status, highlighting alarms for specific IP ranges with down links.
    Only displays entries where the IP is within the specified ranges.
    Expects JSON data.
    """
    print(f"\n--- [ ETHERNET STATUS for {ip_address} ] ---")
    table = PrettyTable(["Port", "Name", "Link Status", "IPv4 Address", "Alarm"])
    table.align = "l"

    if not data or 'device' not in data or 'eth' not in data['device']:
        print("No Ethernet data available or data structure is unexpected.")
        return

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
                if 1 <= last_octet <= 5:
                    is_relevant_ip = True
        # Check for 10.10.x.x series
        elif ipv4addr.startswith("10.10."):
            is_relevant_ip = True
        
        # Only process and display if the IP is relevant
        if is_relevant_ip:
            if link.lower() == "link down":
                alarm = "YES (Port Down in Critical IP Range)"
            table.add_row([port, name, link, ipv4addr, alarm])
    
    if not table._rows:
        print("No Ethernet ports with IP addresses in the specified ranges found.")
    print(table)


def parse_active_faults(data, ip_address):
    """
    Parses active faults, showing only 'Major' or 'Critical' severity.
    Expects JSON data.
    """
    print(f"\n--- [ ACTIVE FAULTS for {ip_address} (Major/Critical Only) ] ---")
    table = PrettyTable(["Name", "Type", "Severity", "Details", "Set Since"])
    table.align = "l"

    if not data or 'faults' not in data or 'status' not in data['faults']:
        print("No fault data available or data structure is unexpected.")
        return

    status_entries = data['faults']['status']
    if not isinstance(status_entries, list):
        status_entries = [status_entries]

    for status in status_entries:
        severity = status.get("severity", "N/A")
        trapstate = status.get("trapstate", "N/A")

        if trapstate.lower() == "set" and (severity.lower() == "major" or severity.lower() == "critical"):
            name = status.get("name", "N/A")
            fault_type = status.get("type", "N/A")
            details = status.get("details", "N/A")
            setsince = status.get("setsince", "N/A")
            table.add_row([name, fault_type, severity, details, setsince])
    
    if not table._rows:
        print("No active Major or Critical faults found.")
    print(table)


# ------------------ Main Execution ------------------ #
def main():
    """
    Main function to orchestrate session creation, data fetching, and parsing
    for a range of IP addresses.
    """
    ip_prefix = "172.19.206."
    start_octet = 1
    end_octet = 45

    for i in range(start_octet, end_octet + 1):
        current_ip = f"{ip_prefix}{i}"
        print(f"\n\n{'='*50}\nProcessing IP: {current_ip}\n{'='*50}")

        session_id = None
        try:
            session_id = create_session(current_ip)
            if not session_id:
                print(f"Skipping {current_ip}: Could not establish a session.")
                continue
            print(f"[+] Session created successfully for {current_ip}: {session_id}")

            # Fetch and parse RF Input Stats (JSON data requested)
            rf_data = fetch_data(current_ip, session_id, "input/rf", json_output=True)
            if rf_data:
                parse_rf_input_stats(rf_data, current_ip)

            # Fetch and parse MOIP Status (JSON data requested)
            moip_data = fetch_data(current_ip, session_id, "input/moip", json_output=True)
            if moip_data:
                parse_moip_status(moip_data, current_ip)

            # Fetch and parse Channel Status (JSON data requested)
            channel_data = fetch_data(current_ip, session_id, "pe", json_output=True)
            if channel_data:
                parse_channel_status(channel_data, current_ip)

            # Fetch and parse Hardware Status (JSON data requested)
            power_data = fetch_data(current_ip, session_id, "device/power", json_output=True)
            if power_data:
                parse_hardware_status(power_data, current_ip)

            # Fetch and parse Ethernet Status (JSON data requested)
            eth_data = fetch_data(current_ip, session_id, "device/eth", json_output=True)
            if eth_data:
                parse_eth_status(eth_data, current_ip)

            # Fetch and parse Active Faults (JSON data requested)
            faults_data = fetch_data(current_ip, session_id, "faults", json_output=True)
            if faults_data:
                parse_active_faults(faults_data, current_ip)

        except Exception as e:
            print(f"[!] An unhandled error occurred while processing {current_ip}: {e}")

if __name__ == "__main__":
    main()

