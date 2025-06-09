import paramiko
import yaml
from flask import Flask, jsonify, request
from flask_cors import CORS # Import CORS to allow frontend access
import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
# Enable CORS for all origins, allowing the frontend to access this API.
# In a production environment, you should restrict this to your frontend's specific origin.
CORS(app)

# Define the full path to PowerShell executable
# This path is standard for Windows and should work across most versions.
POWERSHELL_PATH = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

# Global variable to store configuration loaded from YAML
app_config = {}

def load_config():
    """Loads the monitoring configuration from config.yaml."""
    global app_config
    try:
        # Assuming config.yaml is in the same directory or a known path
        # Adjust path if your Flask app is deployed differently
        config_path = r"C:\Users\DELL\Desktop\VigilSiddhi\backend\windows\config.yaml"
        with open(config_path, "r") as f:
            app_config = yaml.safe_load(f)
        logging.info(f"Configuration loaded successfully from {config_path}")
    except FileNotFoundError:
        logging.error(f"Error: config.yaml not found at {config_path}.")
        app_config = {"hosts": []} # Initialize with empty hosts to prevent errors
    except yaml.YAMLError as e:
        logging.error(f"Error parsing config.yaml: {e}")
        app_config = {"hosts": []}

def check_service_status(ssh_client, service_name):
    """
    Checks the status of a Windows service on the remote host.
    Returns "RUNNING", "STOPPED", "NOT FOUND", or "ERROR_PS:<error_message>".
    """
    command = f'"{POWERSHELL_PATH}" "Get-Service -Name \'{service_name}\' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status"'
    try:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode('utf-8').strip()
        error = stderr.read().decode('utf-8').strip()

        if error:
            logging.warning(f"PowerShell stderr for service '{service_name}': {error}")
            return f"ERROR_PS:{error}"
        elif not output:
            return "NOT FOUND"
        return output.upper()
    except Exception as e:
        logging.error(f"SSH command execution error for service '{service_name}': {e}")
        return f"ERROR_SSH:{e}"

def check_process_status(ssh_client, process_name):
    """
    Checks if a Windows process is running on the remote host.
    Returns "RUNNING", "NOT FOUND", or "ERROR_PS:<error_message>".
    """
    # Using -ErrorAction SilentlyContinue to suppress errors if process not found
    command = f'"{POWERSHELL_PATH}" "if (Get-Process -Name \'{process_name}\' -ErrorAction SilentlyContinue) {{ Write-Output RUNNING }} else {{ Write-Output NOT FOUND }}"'
    try:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode('utf-8').strip()
        error = stderr.read().decode('utf-8').strip()

        if error:
            logging.warning(f"PowerShell stderr for process '{process_name}': {error}")
            return f"ERROR_PS:{error}"
        return output.upper()
    except Exception as e:
        logging.error(f"SSH command execution error for process '{process_name}': {e}")
        return f"ERROR_SSH:{e}"

def get_host_monitoring_data(host):
    """
    Connects to a single host, checks its services/processes, and returns
    a list of issues (alarms) and its individual status.
    """
    ip = host['ip']
    username = host['username']
    password = host['password']
    name = host['name']

    host_issues = []
    host_overall_status = "OK" # Assume OK unless issues are found

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    logging.info(f"Attempting to connect to {name} ({ip})")
    try:
        ssh.connect(ip, username=username, password=password, timeout=10) # Add timeout for robustness
        logging.info(f"Successfully connected to {name}")

        # Check services
        for service in host.get("services", []):
            status = check_service_status(ssh, service)
            if status != "RUNNING":
                host_issues.append({
                    "host_name": name,
                    "server_ip": ip,
                    "item_type": "service",
                    "item_name": service,
                    "status": status,
                    "message": f"Service '{service}' is {status.replace('_', ' ')}",
                    "severity": "ALARM", # Use ALARM for non-running states
                    "timestamp": datetime.datetime.now().isoformat()
                })
                host_overall_status = "ALARM" # Set host status to ALARM if any issue
            logging.info(f"  Service '{service}': {status}")


        # Check processes
        for process in host.get("processes", []):
            status = check_process_status(ssh, process)
            if status != "RUNNING":
                host_issues.append({
                    "host_name": name,
                    "server_ip": ip,
                    "item_type": "process",
                    "item_name": process,
                    "status": status,
                    "message": f"Process '{process}' is {status.replace('_', ' ')}",
                    "severity": "ALARM", # Use ALARM for non-running states
                    "timestamp": datetime.datetime.now().isoformat()
                })
                host_overall_status = "ALARM" # Set host status to ALARM if any issue
            logging.info(f"  Process '{process}': {status}")

    except paramiko.AuthenticationException:
        logging.error(f"Authentication failed for {name} ({ip}). Check username/password.")
        host_issues.append({
            "host_name": name,
            "server_ip": ip,
            "item_type": "connection",
            "item_name": "SSH",
            "status": "AUTH_FAILED",
            "message": "SSH Authentication failed.",
            "severity": "ALARM",
            "timestamp": datetime.datetime.now().isoformat()
        })
        host_overall_status = "ALARM"
    except paramiko.SSHException as e:
        logging.error(f"SSH error connecting to {name} ({ip}): {e}")
        host_issues.append({
            "host_name": name,
            "server_ip": ip,
            "item_type": "connection",
            "item_name": "SSH",
            "status": "SSH_ERROR",
            "message": f"SSH connection error: {e}",
            "severity": "ALARM",
            "timestamp": datetime.datetime.now().isoformat()
        })
        host_overall_status = "ALARM"
    except Exception as e:
        logging.error(f"General connection error to {name} ({ip}): {e}")
        host_issues.append({
            "host_name": name,
            "server_ip": ip,
            "item_type": "connection",
            "item_name": "General",
            "status": "CONNECTION_FAILED",
            "message": f"Connection failed: {e}",
            "severity": "ALARM",
            "timestamp": datetime.datetime.now().isoformat()
        })
        host_overall_status = "ALARM"
    finally:
        ssh.close()
        logging.info(f"Disconnected from {name} ({ip})")

    return {
        "host_name": name,
        "ip": ip,
        "overall_status": host_overall_status,
        "issues": host_issues
    }

@app.route('/get_windows_status', methods=['GET'])
def get_windows_status():
    """
    API endpoint to fetch the status of all configured Windows hosts.
    Returns overall status for the 'WINDOWS' global block and a list of all alarms.
    """
    if not app_config.get("hosts"):
        logging.warning("No Windows hosts configured in config.yaml.")
        return jsonify({
            "overall_status": "UNKNOWN",
            "alarms": [],
            "message": "No Windows hosts configured."
        })

    all_windows_alarms = []
    overall_windows_status = "OK" # Global status for all Windows hosts

    for host in app_config["hosts"]:
        host_data = get_host_monitoring_data(host)
        all_windows_alarms.extend(host_data["issues"])
        if host_data["overall_status"] == "ALARM":
            overall_windows_status = "ALARM" # If any host has issues, the global status is ALARM

    # Transform alarms to match frontend's expected format for the alarm console
    formatted_alarms = []
    for alarm in all_windows_alarms:
        formatted_alarms.append({
            "server_ip": alarm["server_ip"],
            "message": alarm["message"],
            "severity": alarm["severity"],
            "timestamp": alarm["timestamp"],
            "channel_name": alarm["host_name"], # Using host_name as channel_name for display
            "device_name": alarm["item_name"],   # Using item_name (service/process) as device_name
            "type": alarm["item_type"] # Add type for potential filtering if needed later
        })

    logging.info(f"Windows Monitoring Cycle Complete. Overall status: {overall_windows_status}")
    return jsonify({
        "overall_status": overall_windows_status,
        "alarms": formatted_alarms,
        "timestamp": datetime.datetime.now().isoformat()
    })

@app.route('/')
def index():
    return "Windows Monitoring Backend is running. Access /get_windows_status for data."

if __name__ == '__main__':
    load_config() # Load config when the app starts
    app.run(host='0.0.0.0', port=5001, debug=True) # Run on port 5001 to avoid conflict with iLO proxy
