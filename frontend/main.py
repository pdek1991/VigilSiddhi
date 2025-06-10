from flask import Flask, render_template, jsonify
from flask_cors import CORS
import sys
import os
import logging # Import logging module for more detailed server-side logs

# Configure logging for more visibility
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Adjust path to import from the backend directory
# This assumes the structure: project_root/backend/, project_root/frontend/
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(os.path.join(project_root, 'backend'))

# Import your backend classes
from elastic_client import ElasticManager
from ilo_proxy import ILOProxy
from ird_monitor import D9800IRD
from windows_monitor import WindowsMonitor

# Define the absolute path to the Media folder for static files
media_folder_path = os.path.abspath(os.path.join(project_root, 'Media'))
# Define the absolute path to the templates folder
templates_folder_path = os.path.abspath(os.path.join(project_root, 'frontend', 'templates'))

# --- DEBUGGING PATHS ---
logging.info(f"DEBUG: Resolved project_root: {project_root}")
logging.info(f"DEBUG: Resolved media_folder_path: {media_folder_path}")
logging.info(f"DEBUG: Resolved templates_folder_path: {templates_folder_path}")
# --- END DEBUGGING PATHS ---

# --- Initialization ---
# Configure Flask to serve static files from the 'Media' folder
# They will be accessible via the '/media' URL path (e.g., /media/logo.png)
app = Flask(__name__, 
            template_folder=templates_folder_path, # Explicitly set absolute path for templates
            static_folder=media_folder_path, 
            static_url_path='/media')
CORS(app)

# Define paths to initial configuration files
config_dir = os.path.abspath(os.path.join(project_root, 'initial_configs'))

config_file_paths = {
    'channel': os.path.join(config_dir, 'channel_ilo_config.json'),
    'global': os.path.join(config_dir, 'global_ilo_config.json'),
    'windows': os.path.join(config_dir, 'windows_config.yaml')
    # If you have a separate config file for IRDs, add it here:
    # 'ird': os.path.join(config_dir, 'ird_config.json')
}

# --- DEBUGGING CONFIG FILE PATHS ---
logging.info(f"DEBUG: Config file paths: {config_file_paths}")
for key, path in config_file_paths.items():
    logging.info(f"DEBUG: Checking config file '{key}': Does it exist? {os.path.exists(path)}")
    if not os.path.exists(path):
        logging.error(f"ERROR: Config file '{path}' does NOT exist. Please check your initial_configs folder.")
# --- END DEBUGGING CONFIG FILE PATHS ---


# Initialize Elasticsearch connection and backend classes
try:
    # Ensure Elasticsearch is running and accessible at this host/port
    es_manager = ElasticManager(hosts=["http://192.168.56.30:9200"])
    es_client = es_manager.get_client()

    # IMPORTANT: Load initial configurations into Elasticsearch on app startup.
    # This ensures ILOProxy, IRDMonitor, and WindowsMonitor can find their configs.
    logging.info("Attempting to load initial configurations into Elasticsearch...")
    es_manager.load_initial_configs(config_file_paths)
    logging.info("Initial configurations loaded successfully.")
    
    # Instantiate backend service classes
    ilo_service = ILOProxy(es_client)
    ird_service = D9800IRD(es_client)
    windows_service = WindowsMonitor(es_client)
    
except Exception as e:
    # Log a fatal error if services cannot be initialized
    logging.error(f"FATAL: Could not initialize backend services. {e}")
    # Set services to None to handle gracefully in API endpoints
    ilo_service = None
    ird_service = None
    windows_service = None

# --- HTML Serving Endpoints ---
@app.route('/')
def index():
    # Renders the main dashboard HTML page
    return render_template('index.html')

@app.route('/alarm_console_fullscreen')
def alarm_console_fullscreen():
    # Renders the fullscreen alarm console HTML page
    # Explicitly specify the path to ensure it's found within the templates directory
    try:
        return render_template('alarm_console_fullscreen.html')
    except Exception as e:
        logging.error(f"ERROR: Failed to render alarm_console_fullscreen.html: {e}")
        # Return a generic error page or message
        return "<h1>Error: Could not load Alarm Console</h1><p>Please check server logs for details.</p>", 500


# --- API Endpoints ---

# Endpoint for a single iLO device's status
@app.route('/api/v1/get_ilo_status/<string:channel_id_str>/<string:device_id>', methods=['GET'])
def get_ilo_status(channel_id_str, device_id):
    """
    Fetches the status of a single iLO device based on channel ID and device ID.
    Returns JSON response with status, alarms, and any errors.
    """
    if not ilo_service:
        # Return service unavailable if ILOProxy failed to initialize
        logging.error("iLO service not available during get_ilo_status API call.")
        return jsonify({"status": "error", "message": "iLO service not available"}), 503
    
    # Call the correct method in ILOProxy to get single device status
    response_data, status_code = ilo_service.get_status_for_single_device(channel_id_str, device_id)
    return jsonify(response_data), status_code

# Endpoint for collective iLO status (groups like VS_M, Encoder M, etc.)
@app.route('/api/v1/get_collective_ilo_status/<string:block_type>', methods=['GET'])
def get_collective_ilo_status(block_type):
    """
    Fetches the aggregated status for a collective group of iLO devices (e.g., all 'VS_M' devices).
    Returns JSON response with collective status, alarms, and any errors.
    """
    if not ilo_service:
        # Return service unavailable if ILOProxy failed to initialize
        logging.error("iLO service not available during get_collective_ilo_status API call.")
        return jsonify({"status": "error", "message": "iLO service not available"}), 503
    
    # Call the method with the correct name: get_status_for_collective
    response_data, status_code = ilo_service.get_status_for_collective(block_type)
    return jsonify(response_data), status_code

# Endpoint for Windows monitoring status
@app.route('/api/v1/get_windows_status', methods=['GET'])
def get_windows_status():
    """
    Fetches the overall status and alarms for all configured Windows hosts.
    Returns formatted JSON response.
    """
    if not windows_service:
        # Return service unavailable if WindowsMonitor failed to initialize
        logging.error("Windows monitoring service not available during get_windows_status API call.")
        return jsonify({"status": "error", "message": "Windows monitoring service not available"}), 503
    
    results = windows_service.get_all_statuses()
    
    # Determine overall status for the frontend
    overall_status = "ok"
    # Check if any host status is not 'ok' in the detailed status_data
    if any(s['overall_status'] != 'OK' for s in results.get('status_data', [])):
        overall_status = "alarm" # If any host has issues, overall status is alarm
        
    return jsonify({
        "overall_status": overall_status,
        "alarms": results.get('alarms', []), # Ensure 'alarms' key exists and is a list
        "details": results.get('status_data', []) # Ensure 'status_data' key exists and is a list
    })
    
# Endpoint for IRD monitoring status
@app.route('/api/v1/get_ird_status', methods=['GET'])
def get_ird_status():
    """
    Fetches the overall status and alarms for all configured Cisco D9800 IRD devices.
    Returns raw JSON response from the IRD monitor.
    """
    if not ird_service:
        # Return service unavailable if D9800IRD failed to initialize
        logging.error("IRD monitoring service not available during get_ird_status API call.")
        return jsonify({"status": "error", "message": "IRD monitoring service not available"}), 503
    
    results = ird_service.get_all_statuses()
    # The IRD service returns a dictionary with 'status_data' and 'alarms'.
    # You might want to add an 'overall_status' here as well for consistency,
    # similar to how it's done for Windows status.
    # For now, returning the raw results.
    return jsonify(results)


if __name__ == '__main__':
    # Run the Flask application. Host '0.0.0.0' makes it accessible externally.
    # debug=True provides helpful error messages during development.
    app.run(host='0.0.0.0', port=5000, debug=True)

