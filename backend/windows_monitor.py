import logging
import paramiko
import datetime
from datetime import datetime, timezone

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class WindowsMonitor:
    """
    Monitors Windows hosts by checking the status of specified services and processes
    via SSH and PowerShell commands.
    """
    # Define the full path to PowerShell executable for Windows monitoring
    # This path might vary depending on the Windows system setup, but this is a common default.
    POWERSHELL_PATH = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    def __init__(self, es_client):
        """
        Initializes the WindowsMonitor with an Elasticsearch client.

        Args:
            es_client: An instance of the Elasticsearch client.
        """
        self.es = es_client
        self.hosts = self._load_config()

    def _load_config(self):
        """Loads Windows host configurations from Elasticsearch."""
        hosts = []
        try:
            # Fetch all documents from the 'windows_config' index
            res = self.es.search(index="windows_config", body={"query": {"match_all": {}}}, size=1000)
            for hit in res['hits']['hits']:
                # Append the source document of each hit
                hosts.append(hit['_source'])
            logging.info(f"Loaded {len(hosts)} Windows host configurations from Elasticsearch.")
            return hosts
        except Exception as e:
            logging.error(f"Failed to load Windows configs from Elasticsearch: {e}")
            return []

    def _run_powershell_command(self, hostname, username, password, command):
        """
        Executes a PowerShell command on a remote Windows host via SSH using Paramiko.

        Args:
            hostname (str): The IP address or hostname of the remote Windows machine.
            username (str): The username for SSH authentication.
            password (str): The password for SSH authentication.
            command (str): The PowerShell command to execute.

        Returns:
            str: The stdout of the command if successful, None otherwise.
        """
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy()) # Automatically add host keys
        output = None
        try:
            client.connect(hostname, username=username, password=password, timeout=10)
            # Execute the PowerShell command via cmd.exe to ensure proper execution environment
            stdin, stdout, stderr = client.exec_command(f"{self.POWERSHELL_PATH} -Command \"{command}\"")
            output = stdout.read().decode('utf-8').strip()
            error = stderr.read().decode('utf-8').strip()

            if error:
                logging.error(f"Error executing command on {hostname}: {error}")
                return None
            return output
        except paramiko.AuthenticationException:
            logging.error(f"Authentication failed for {username}@{hostname}")
            return None
        except paramiko.SSHException as e:
            logging.error(f"SSH connection error to {hostname}: {e}")
            return None
        except Exception as e:
            logging.error(f"An unexpected error occurred while running command on {hostname}: {e}")
            return None
        finally:
            if client:
                client.close()

    def _get_service_status(self, hostname, username, password, service_name):
        """
        Gets the status of a specific Windows service.

        Args:
            hostname (str): The IP address or hostname of the remote Windows machine.
            username (str): The username for SSH authentication.
            password (str): The password for SSH authentication.
            service_name (str): The name of the service to check.

        Returns:
            str: The status of the service (e.g., "Running", "Stopped", "Unknown").
        """
        command = f"Get-Service -Name '{service_name}' | Select-Object -ExpandProperty Status"
        output = self._run_powershell_command(hostname, username, password, command)
        return output if output else "Unknown"

    def _get_process_status(self, hostname, username, password, process_name):
        """
        Checks if a specific process is running on the Windows host.

        Args:
            hostname (str): The IP address or hostname of the remote Windows machine.
            username (str): The username for SSH authentication.
            password (str): The password for SSH authentication.
            process_name (str): The name of the process to check.

        Returns:
            bool: True if the process is running, False otherwise.
        """
        # Use -ErrorAction SilentlyContinue to prevent script from failing if process not found
        command = f"Get-Process -Name '{process_name}' -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"
        output = self._run_powershell_command(hostname, username, password, command)
        try:
            # If output is not digits, it means process was not found or an error occurred.
            # In such case, int(output) will raise ValueError.
            return int(output) > 0 if output and output.strip().isdigit() else False
        except ValueError:
            logging.warning(f"Could not parse process count for '{process_name}' on {hostname}. Output: '{output}'")
            return False

    def get_all_statuses(self):
        """
        Checks status of all configured Windows hosts for services and processes,
        generates alarms, and stores trend and alarm data in Elasticsearch.

        Returns:
            dict: A dictionary containing 'status_data' (list of dictionaries for each host)
                  and 'alarms' (list of dictionaries for all generated alarms).
        """
        all_statuses = []
        all_alarms = []

        for host_config in self.hosts:
            host_ip = host_config.get("ip")
            host_name = host_config.get("name", host_ip) # Use IP as name if not provided
            username = host_config.get("username")
            password = host_config.get("password")
            services_to_monitor = host_config.get("services_to_monitor", [])
            processes_to_monitor = host_config.get("processes_to_monitor", [])

            if not host_ip or not username or not password:
                logging.warning(f"Skipping host config for {host_name}: Missing IP, username, or password.")
                continue

            logging.info(f"Monitoring Windows Host: {host_name} ({host_ip})")

            host_issues = [] # Issues for the current host
            current_host_overall_status = "OK"
            current_timestamp = datetime.now(timezone.utc).isoformat() # Use UTC for consistency

            # Check services
            for service_name in services_to_monitor:
                status = self._get_service_status(host_ip, username, password, service_name)
                if status.lower() != "running":
                    logging.warning(f"[{host_name}] Service '{service_name}' is {status}.")
                    host_issues.append({
                        "server_ip": host_ip,
                        "host_name": host_name,
                        "item_type": "Service",
                        "item_name": service_name,
                        "message": f"Service '{service_name}' is {status}.",
                        "severity": "CRITICAL",
                        "timestamp": current_timestamp
                    })
                    current_host_overall_status = "ALARM"

            # Check processes
            for process_name in processes_to_monitor:
                is_running = self._get_process_status(host_ip, username, password, process_name)
                if not is_running:
                    logging.warning(f"[{host_name}] Process '{process_name}' is not running.")
                    host_issues.append({
                        "server_ip": host_ip,
                        "host_name": host_name,
                        "item_type": "Process",
                        "item_name": process_name,
                        "message": f"Process '{process_name}' is not running.",
                        "severity": "MAJOR",
                        "timestamp": current_timestamp
                    })
                    current_host_overall_status = "ALARM"
            
            host_status_entry = {
                "timestamp": current_timestamp,
                "host_ip": host_ip,
                "host_name": host_name,
                "overall_status": current_host_overall_status,
                "issues": host_issues
            }
            all_statuses.append(host_status_entry)
            all_alarms.extend(host_issues) # Add current host's issues to the global alarm list

            # Store trend data for the current host
            try:
                self.es.index(index="windows_trend", document=host_status_entry)
                logging.info(f"Trend data for Windows host {host_name} ({host_ip}) written to Elasticsearch 'windows_trend' index.")
            except Exception as e:
                logging.error(f"Failed to write trend data for {host_name} to Elasticsearch: {e}")

            # Store generated alarms in active_alarms and historical_alarms indices
            for alarm in host_issues:
                try:
                    # Modify alarm for active_alarms (e.g., add a unique ID or use specific fields)
                    # For simplicity, using the same alarm structure for both active and historical
                    self.es.index(index="active_alarms", document=alarm)
                    self.es.index(index="historical_alarms", document=alarm)
                    logging.info(f"Alarm for Windows host {host_name} (Item: {alarm.get('item_name', 'N/A')}, Severity: {alarm.get('severity', 'N/A')}) written to Elasticsearch.")
                except Exception as e:
                    logging.error(f"Failed to write alarm for {host_name} to Elasticsearch: {e}")

        return {"status_data": all_statuses, "alarms": all_alarms}