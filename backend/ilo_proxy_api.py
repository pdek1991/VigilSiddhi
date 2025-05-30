from flask import Flask, jsonify, request
from flask_cors import CORS
import requests
import json
import logging
import urllib3
import sys

# Suppress insecure request warning for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging for better visibility
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
# Enable CORS for all origins. In production, restrict this to your frontend's origin.
CORS(app) 

# --- IMPORTANT: Configure your iLO server credentials here ---
# This dictionary maps iLO IP addresses to their respective usernames and passwords.
# This information is kept on the backend and is NOT exposed to the frontend.
ILO_CREDENTIALS = {
    "192.168.1.10": {"username": "admin", "password": "password1"}, # VS M (Channel 1)
    "192.168.1.11": {"username": "admin", "password": "password2"}, # VS P (Channel 1)
    "192.168.1.12": {"username": "admin", "password": "password3"}, # VS B (Channel 1)
    # Add more iLO servers here as needed for other channels/blocks
    # Example for Channel 2:
    # "192.168.1.20": {"username": "admin", "password": "password_ch2_m"}, # VS M (Channel 2)
    # "192.168.1.21": {"username": "admin", "password": "password_ch2_p"}, # VS P (Channel 2)
    # "192.168.1.22": {"username": "admin", "password": "password_ch2_b"}, # VS B (Channel 2)
}

def get_alarm_decision(severity):
    """
    Determines a simplified alarm decision based on Redfish severity.
    Maps Redfish severities to 'Critical', 'Warning', 'OK', 'Informational', 'Unknown'.
    """
    severity_lower = str(severity).lower()
    if severity_lower == "critical":
        return "Critical"
    elif severity_lower == "warning":
        return "Warning"
    elif severity_lower in ["ok", "informational"]:
        return "OK" # For dashboard display, 'OK' and 'Informational' can be grouped as 'OK'
    else:
        return "Unknown"

def get_overall_status_from_health(current_overall, new_status_decision):
    """
    Updates the overall status based on a new status decision (Critical, Warning, OK, Unknown).
    Prioritizes 'alarm' (Critical) > 'warning' > 'unknown' > 'ok'.
    """
    status_priority = {
        "alarm": 4,       # Highest priority (from Critical)
        "warning": 3,
        "unknown": 2,     # Unknown should be higher than OK, as it implies potential issue
        "ok": 1           # Lowest priority
    }

    current_priority = status_priority.get(current_overall.lower(), 0)
    new_priority = status_priority.get(new_status_decision.lower(), 0)

    if new_priority > current_priority:
        return new_status_decision.lower()
    return current_overall

def process_resource_health(session, ilo_ip, resource_uri, current_overall_status, visited_uris):
    """
    Fetches a Redfish resource, checks its health, and updates the overall status.
    Recursively checks members and linked resources if it's a collection or complex resource.
    Uses visited_uris to prevent infinite loops in circular references.
    """
    full_resource_url = f"https://{ilo_ip}{resource_uri}"

    # Prevent infinite recursion for circular references
    if full_resource_url in visited_uris:
        logging.debug(f"[{ilo_ip}] Skipping already visited URI: {full_resource_url}")
        return current_overall_status
    visited_uris.add(full_resource_url)

    try:
        response = session.get(full_resource_url)
        response.raise_for_status()
        data = response.json()

        # Check health of the current resource itself
        health = data.get('Status', {}).get('Health')
        if health and health.lower() != 'ok':
            logging.warning(f"[{ilo_ip}] Health issue found for {resource_uri}: Health={health}")
            current_overall_status = get_overall_status_from_health(current_overall_status, health)
        elif health:
            logging.debug(f"[{ilo_ip}] Health OK for {resource_uri}")
            current_overall_status = get_overall_status_from_health(current_overall_status, health)

        # Iterate through members if it's a collection
        if 'Members' in data and isinstance(data['Members'], list):
            for member in data['Members']:
                member_id = member.get('@odata.id')
                if member_id and member_id.startswith('/redfish/v1/'): # Ensure it's a relative Redfish URI
                    current_overall_status = process_resource_health(session, ilo_ip, member_id, current_overall_status, visited_uris)
        
        # Generic traversal for linked resources/sub-collections
        # Look for properties that are objects and contain an '@odata.id'
        # This helps discover components like EthernetInterfaces, Processors, Memory, Storage, Power, Thermal etc.
        for key, value in data.items():
            if isinstance(value, dict) and '@odata.id' in value and key not in ['Links', 'Actions', 'Oem']:
                linked_uri = value['@odata.id']
                if linked_uri.startswith('/redfish/v1/') and linked_uri not in visited_uris:
                    # Avoid re-processing top-level collections or log services that are handled separately
                    # This check prevents redundant calls for already processed main collections or logs
                    if not any(linked_uri.startswith(f"/redfish/v1/{c.lower()}") for c in ["systems", "chassis", "managers", "logservices"]):
                        current_overall_status = process_resource_health(session, ilo_ip, linked_uri, current_overall_status, visited_uris)
            elif isinstance(value, list) and key not in ['Members']: # Check arrays that might contain linked resources
                for item in value:
                    if isinstance(item, dict) and '@odata.id' in item:
                        linked_uri = item['@odata.id']
                        if linked_uri.startswith('/redfish/v1/') and linked_uri not in visited_uris:
                            if not any(linked_uri.startswith(f"/redfish/v1/{c.lower()}") for c in ["systems", "chassis", "managers", "logservices"]):
                                current_overall_status = process_resource_health(session, ilo_ip, linked_uri, current_overall_status, visited_uris)


    except requests.exceptions.RequestException as e:
        logging.warning(f"[{ilo_ip}] Failed to fetch resource {full_resource_url}: {e}")
        current_overall_status = get_overall_status_from_health(current_overall_status, "Unknown")
    except json.JSONDecodeError as e:
        logging.warning(f"[{ilo_ip}] Failed to parse JSON from {full_resource_url}: {e}")
        current_overall_status = get_overall_status_from_health(current_overall_status, "Unknown")
    except Exception as e:
        logging.exception(f"[{ilo_ip}] An unexpected error occurred while processing {full_resource_url}.")
        current_overall_status = get_overall_status_from_health(current_overall_status, "Unknown")

    return current_overall_status

def fetch_ilo_alarms(ilo_ip, username, password):
    """
    Fetches hardware-related alarms and health status from various Redfish API endpoints.
    Returns an overall status based on the most severe issue found.
    """
    server_base_url = f"https://{ilo_ip}"
    redfish_service_root = f"{server_base_url}/redfish/v1"
    
    overall_status = "ok" # Default to OK
    visited_uris = set() # To prevent infinite loops in Redfish graph traversal

    logging.info(f"[{ilo_ip}] Starting comprehensive health and alarm collection.")

    try:
        session = requests.Session()
        session.auth = (username, password)
        session.verify = False # Disable SSL verification (use with caution!)
        session.timeout = 10 

        service_root_response = session.get(redfish_service_root)
        service_root_response.raise_for_status()
        service_root_data = service_root_response.json()

        # Start checking from top-level collections (Systems, Chassis, Managers)
        # These are usually the entry points to hardware health.
        top_level_collections = []
        
        systems_uri = service_root_data.get('Systems', {}).get('@odata.id')
        if systems_uri: top_level_collections.append(systems_uri)
        
        chassis_uri = service_root_data.get('Chassis', {}).get('@odata.id')
        if chassis_uri: top_level_collections.append(chassis_uri)
        
        managers_uri = service_root_data.get('Managers', {}).get('@odata.id')
        if managers_uri: top_level_collections.append(managers_uri)

        # Process top-level collections and their members recursively
        for uri in top_level_collections:
            overall_status = process_resource_health(session, ilo_ip, uri, overall_status, visited_uris)

        # Additionally, fetch Integrated Management Log (IML) and Alert Event Log entries
        # These are specific log services and often contain detailed events not always
        # directly reflected in component 'Health' status.
        
        # Need to re-fetch system_id and manager_id if they were not successfully obtained
        # during the initial recursive traversal for log services.
        system_id = None
        if systems_uri:
            try:
                systems_response = session.get(f"{server_base_url}{systems_uri}")
                systems_response.raise_for_status()
                systems_data = systems_response.json()
                if 'Members' in systems_data and len(systems_data['Members']) > 0:
                    system_id = systems_data['Members'][0].get('@odata.id')
            except requests.exceptions.RequestException as e:
                logging.warning(f"[{ilo_ip}] Could not get System ID for log services: {e}")

        if system_id:
            # Fetch Integrated Management Log (IML) entries
            iml_log_uri = f"{server_base_url}{system_id}/LogServices/IML/Entries"
            try:
                iml_response = session.get(iml_log_uri)
                iml_response.raise_for_status()
                iml_data = iml_response.json()
                if 'Members' in iml_data:
                    for entry in iml_data['Members']:
                        decision = get_alarm_decision(entry.get('Severity', 'N/A'))
                        overall_status = get_overall_status_from_health(overall_status, decision)
                        if decision != "OK":
                            logging.warning(f"[{ilo_ip}] IML Alarm: {entry.get('Message')} (Severity: {entry.get('Severity')})")
                logging.info(f"[{ilo_ip}] Successfully checked IML entries.")
            except requests.exceptions.RequestException as e:
                logging.warning(f"[{ilo_ip}] Failed to fetch IML logs: {e}")
            except json.JSONDecodeError as e:
                logging.warning(f"[{ilo_ip}] Failed to parse IML JSON response: {e}")

            # Fetch Alert Event Log entries
            alert_log_uri = f"{server_base_url}{system_id}/LogServices/Event/Entries"
            try:
                alert_response = session.get(alert_log_uri)
                alert_response.raise_for_status()
                alert_data = alert_response.json()
                if 'Members' in alert_data:
                    for entry in alert_data['Members']:
                        if entry.get('EventType') == 'Alert':
                            decision = get_alarm_decision(entry.get('Severity', 'N/A'))
                            overall_status = get_overall_status_from_health(overall_status, decision)
                            if decision != "OK":
                                logging.warning(f"[{ilo_ip}] Alert Log Alarm: {entry.get('Message')} (Severity: {entry.get('Severity')})")
                logging.info(f"[{ilo_ip}] Successfully checked Alert Event entries.")
            except requests.exceptions.RequestException as e:
                logging.warning(f"[{ilo_ip}] Failed to fetch Alert Event logs: {e}")
            except json.JSONDecodeError as e:
                logging.warning(f"[{ilo_ip}] Failed to parse Alert Event JSON response: {e}")

            # Fetch iLO Event Log (IEL) entries (from Manager)
            manager_id = None
            if managers_uri:
                try:
                    managers_response = session.get(f"{server_base_url}{managers_uri}")
                    managers_response.raise_for_status()
                    managers_data = managers_response.json()
                    if 'Members' in managers_data and len(managers_data['Members']) > 0:
                        manager_id = managers_data['Members'][0].get('@odata.id')
                except requests.exceptions.RequestException as e:
                    logging.warning(f"[{ilo_ip}] Could not get Manager ID for log services: {e}")

            if manager_id:
                iel_log_uri = f"{server_base_url}{manager_id}/LogServices/IEL/Entries"
                try:
                    iel_response = session.get(iel_log_uri)
                    iel_response.raise_for_status()
                    iel_data = iel_response.json()
                    if 'Members' in iel_data:
                        for entry in iel_data['Members']:
                            decision = get_alarm_decision(entry.get('Severity', 'N/A'))
                            overall_status = get_overall_status_from_health(overall_status, decision)
                            if decision != "OK":
                                logging.warning(f"[{ilo_ip}] IEL Alarm: {entry.get('Message')} (Severity: {entry.get('Severity')})")
                    logging.info(f"[{ilo_ip}] Successfully checked IEL entries.")
                except requests.exceptions.RequestException as e:
                    logging.warning(f"[{ilo_ip}] Failed to fetch iLO Event logs: {e}")
                except json.JSONDecodeError as e:
                    logging.warning(f"[{ilo_ip}] Failed to parse iLO Event JSON response: {e}")

    except requests.exceptions.Timeout:
        logging.error(f"[{ilo_ip}] Connection timed out during initial service root fetch.")
        overall_status = "unknown"
    except requests.exceptions.ConnectionError as e:
        logging.error(f"[{ilo_ip}] Connection error during initial service root fetch: {e}")
        overall_status = "unknown"
    except requests.exceptions.HTTPError as e:
        logging.error(f"[{ilo_ip}] HTTP error {e.response.status_code}: {e.response.reason} during initial service root fetch. Response: {e.response.text[:200]}...")
        overall_status = "unknown"
    except json.JSONDecodeError as e:
        logging.error(f"[{ilo_ip}] Failed to parse JSON response from iLO service root: {e}")
        overall_status = "unknown"
    except Exception as e:
        logging.exception(f"[{ilo_ip}] An unexpected error occurred during overall collection.")
        overall_status = "unknown"
    finally:
        if 'session' in locals():
            session.close()
    
    logging.info(f"[{ilo_ip}] Final overall status determined: {overall_status}")
    return overall_status

@app.route('/get_ilo_status/<string:ilo_ip>', methods=['GET'])
def get_ilo_status(ilo_ip):
    """
    Flask endpoint to get the overall status of a specific iLO server.
    """
    credentials = ILO_CREDENTIALS.get(ilo_ip)
    if not credentials:
        logging.error(f"Credentials not found for iLO IP: {ilo_ip}")
        return jsonify({"status": "error", "message": "iLO IP not configured"}), 404

    username = credentials['username']
    password = credentials['password']

    status = fetch_ilo_alarms(ilo_ip, username, password)
    return jsonify({"ip": ilo_ip, "status": status})

if __name__ == '__main__':
    # Run the Flask app on port 5000
    app.run(host='0.0.0.0', port=5000, debug=False)
