VigilSiddhi is a powerful, real-time monitoring and dashboard application designed to keep a close eye on your IT infrastructure. It provides comprehensive insights into the health and status of Cisco D9800 IRD devices, Windows hosts, and HPE iLO servers. This document details its features, data flow, API endpoints, and Elasticsearch index formats.

Key Features 🚀
VigilSiddhi offers a robust set of features to ensure comprehensive monitoring:

Cisco D9800 IRD Monitoring: Tracks critical RF data like C/N Margin, Signal Level, and Input Rate, generating and logging alarms based on predefined thresholds. It also stores historical trend data for analysis.
Windows Host Monitoring: Oversees Windows hosts by checking service and process statuses, collecting system information, disk usage, and network statistics. It generates alarms for anomalies.
HPE iLO Monitoring: Fetches active Integrated Lights-Out (iLO) Management Log (IML) alarms and provides collective status for iLO device groups with a reliable retry mechanism.
Centralized Configuration Management: Manages configurations for channels, global groups, and Windows hosts, initially loaded from JSON/YAML files and dynamically accessible via API.
Real-time Web Dashboard: A responsive Flask-based web interface for visualizing the health of all monitored devices, displaying overall status, active alarms, and detailed information. Includes a full-screen alarm console.
Robust Logging and Error Handling: Provides comprehensive logging for debugging and operational insights, handling connection errors gracefully.
Data Flow 🌊
VigilSiddhi employs a client-server architecture with Elasticsearch serving as the central data store.

Configuration Loading
The ElasticManager (elastic_client.py) connects to Elasticsearch and loads initial configurations from channel_ilo_config.json, global_ilo_config.json, and windows_config.yaml into dedicated Elasticsearch indices: channel_config, global_config, and windows_config. The ird_monitor.py also fetches its configurations from the ird_config Elasticsearch index.

Monitoring Data Collection
IRD Monitoring: The D9800IRD class (ird_monitor.py) periodically fetches status data, RF parameters, and channel names from configured Cisco D9800 IRD devices via HTTP/HTTPS.
Windows Monitoring: The WindowsMonitor class (windows_monitor.py) uses SSH to execute PowerShell commands on Windows hosts, gathering service, process, disk, and network information.
iLO Monitoring: The ILOProxy class (ilo_proxy.py) interacts with HPE iLO devices to retrieve active IML alarms and compute collective group statuses.
Data Processing and Storage
Monitors (IRD, Windows) process raw collected data. Alarms and issues are generated based on predefined logic and thresholds. All collected monitoring data (trend data) and generated alarms are pushed to Elasticsearch into the ird_trend, windows_trend, active_alarms, and historical_alarms indices.

API Exposure (Backend)
The main.py Flask application acts as the backend server. It initializes instances of ElasticManager, ILOProxy, D9800IRD, and WindowsMonitor, exposing RESTful API endpoints for the frontend to query real-time status, alarms, and configuration information.

Frontend Visualization (Dashboard)
The index.html and alarm_console_fullscreen.html files represent the web frontend. These HTML pages utilize JavaScript to make asynchronous calls to the Flask API endpoints, dynamically rendering the retrieved data on the dashboard for system health overviews and detailed alarm information.

API Endpoints 🔗
The Flask application exposes a variety of API endpoints:

Dashboard & HTML Endpoints
/ (GET): Serves the main dashboard HTML page (index.html).
/alarm_console_fullscreen (GET): Serves the full-screen alarm console HTML page (alarm_console_fullscreen.html).
Monitoring Status Endpoints
/api/v1/get_windows_status (GET): Fetches the overall status and details for all configured Windows hosts.
/api/v1/get_ilo_collective_status (GET): Fetches the collective status and alarms for configured iLO device groups.
/api/v1/get_ird_status (GET): Fetches the overall status and alarms for all configured Cisco D9800 IRD devices.
/api/v1/get_active_alarms_dashboard (GET): Fetches active alarms relevant for display on the dashboard.
Configuration Management Endpoints
/api/v1/configs/all (GET): Retrieves all configurations (channel, global, windows).
/api/v1/configs/channel (GET): Retrieves all channel configurations.
/api/v1/configs/global (GET): Retrieves all global group configurations.
/api/v1/configs/windows (GET): Retrieves all Windows host configurations.
/api/v1/configs/channel/&lt;int:channel_id> (GET): Retrieves a specific channel configuration by channel_id.
/api/v1/configs/global/&lt;string:group_id> (GET): Retrieves a specific global group configuration by group_id.
/api/v1/configs/windows/&lt;string:host_name> (GET): Retrieves a specific Windows host configuration by host_name.
/api/v1/configs/channel (POST): Adds or updates a channel configuration.
/api/v1/configs/global (POST): Adds or updates a global group configuration.
/api/v1/configs/windows (POST): Adds or updates a Windows host configuration.
/api/v1/configs/channel/&lt;int:channel_id> (DELETE): Deletes a channel configuration by channel_id.
/api/v1/configs/global/&lt;string:group_id> (DELETE): Deletes a global group configuration by group_id.
/api/v1/configs/windows/&lt;string:host_name> (DELETE): Deletes a Windows host configuration by host_name.
Elasticsearch Index Formats 📊
This section details the mappings for the Elasticsearch indices used by VigilSiddhi. The base Elasticsearch URL used in the examples is http://192.168.56.30:9200.

ird_trend Index
Purpose: Stores time-series trend data for Cisco D9800 IRD devices.

JSON

{
  "mappings": {
    "properties": {
      "@timestamp": {
        "type": "date"
      },
      "system_id": {
        "type": "integer"
      },
      "channel_name": {
        "type": "text"
      },
      "cn_margin": {
        "type": "float"
      },
      "signal_level": {
        "type": "float"
      },
      "input_rate": {
        "type": "long"
      }
    }
  }
}
channel_config Index
Purpose: Stores configurations for various channels, each potentially containing multiple devices.

JSON

{
  "mappings": {
    "properties": {
      "channel_id": {
        "type": "integer"
      },
      "devices": {
        "type": "nested",
        "properties": {
          "id": {
            "type": "keyword"
          },
          "ip": {
            "type": "ip"
          },
          "username": {
            "type": "keyword"
          },
          "password": {
            "type": "keyword"
          }
        }
      }
    }
  }
}
global_config Index
Purpose: Stores global group configurations, possibly for grouping different types of devices or services.

JSON

{
  "mappings": {
    "properties": {
      "id": {
        "type": "keyword"
      },
      "name": {
        "type": "text"
      },
      "type": {
        "type": "keyword"
      },
      "additional_ips": {
        "type": "nested",
        "properties": {
          "ip": {
            "type": "ip"
          },
          "username": {
            "type": "keyword"
          },
          "password": {
            "type": "keyword"
          }
        }
      }
    }
  }
}
windows_config Index
Purpose: Stores configurations for Windows hosts, including their IP addresses, credentials, and lists of services/processes to monitor.

JSON

{
  "mappings": {
    "properties": {
      "name": {
        "type": "keyword"
      },
      "ip": {
        "type": "ip"
      },
      "username": {
        "type": "keyword"
      },
      "password": {
        "type": "keyword"
      },
      "services": {
        "type": "keyword"
      },
      "processes": {
        "type": "keyword"
      }
    }
  }
}
ird_config Index
Purpose: Stores configurations specific to IRD devices, used by ird_monitor.py to fetch devices to monitor.

JSON

{
  "mappings": {
    "properties": {
      "system_id": {
        "type": "keyword"
      },
      "ip_address": {
        "type": "ip"
      },
      "username": {
        "type": "keyword"
      },
      "password": {
        "type": "keyword"
      },
      "channel_name": {
        "type": "text"
      }
    }
  }
}
active_alarms Index
Purpose: Stores currently active alarms for immediate display on the dashboard.

JSON

{
  "mappings": {
    "properties": {
      "@timestamp": {
        "type": "date"
      },
      "alarm_id": {
        "type": "keyword"
      },
      "source": {
        "type": "keyword"
      },
      "server_ip": {
        "type": "ip"
      },
      "message": {
        "type": "text"
      },
      "severity": {
        "type": "keyword"
      },
      "channel_name": {
        "type": "keyword"
      },
      "device_name": {
        "type": "keyword"
      },
      "group_id": {
        "type": "keyword"
      }
    }
  }
}
historical_alarms Index
Purpose: Stores a complete history of all generated alarms.

JSON

{
  "mappings": {
    "properties": {
      "@timestamp": {
        "type": "date"
      },
      "alarm_id": {
        "type": "keyword"
      },
      "source": {
        "type": "keyword"
      },
      "server_ip": {
        "type": "ip"
      },
      "message": {
        "type": "text"
      },
      "severity": {
        "type": "keyword"
      },
      "channel_name": {
        "type": "keyword"
      },
      "device_name": {
        "type": "keyword"
      },
      "group_id": {
        "type": "keyword"
      }
    }
  }
}
Create Index with cURL 🛠️
You can create the necessary Elasticsearch indices using the following curl commands. Remember to replace http://192.168.56.30:9200 with your Elasticsearch host and port if different.

Bash

curl -X PUT "http://192.168.56.30:9200/ird_trend" -H "Content-Type: application/json" -d "{\"mappings\":{\"properties\":{\"@timestamp\":{\"type\":\"date\"},\"system_id\":{\"type\":\"integer\"},\"channel_name\":{\"type\":\"text\"},\"cn_margin\":{\"type\":\"float\"},\"signal_level\":{\"type\":\"float\"},\"input_rate\":{\"type\":\"long\"}}}}"
Bash

curl -X PUT "http://192.168.56.30:9200/channel_config" -H "Content-Type: application/json" -d "{\"mappings\":{\"properties\":{\"channel_id\":{\"type\":\"integer\"},\"devices\":{\"type\":\"nested\",\"properties\":{\"id\":{\"type\":\"keyword\"},\"ip\":{\"type\":\"ip\"},\"username\":{\"type\":\"keyword\"},\"password\":{\"type\":\"keyword\"}}}}}}"
Bash

curl -X PUT "http://192.168.56.30:9200/global_config" -H "Content-Type: application/json" -d "{\"mappings\":{\"properties\":{\"id\":{\"type\":\"keyword\"},\"name\":{\"type\":\"text\"},\"type\":{\"type\":\"keyword\"},\"additional_ips\":{\"type\":\"nested\",\"properties\":{\"ip\":{\"type\":\"ip\"},\"username\":{\"type\":\"keyword\"},\"password\":{\"type\":\"keyword\"}}}}}}"
Bash

curl -X PUT "http://192.168.56.30:9200/windows_config" -H "Content-Type: application/json" -d "{\"mappings\":{\"properties\":{\"name\":{\"type\":\"keyword\"},\"ip\":{\"type\":\"ip\"},\"username\":{\"type\":\"keyword\"},\"password\":{\"type\":\"keyword\"},\"services\":{\"type\":\"keyword\"},\"processes\":{\"type\":\"keyword\"}}}}"
Bash

curl -X PUT "http://192.168.56.30:9200/ird_config" -H "Content-Type: application/json" -d "{\"mappings\":{\"properties\":{\"system_id\":{\"type\":\"keyword\"},\"ip_address\":{\"type\":\"ip\"},\"username\":{\"type\":\"keyword\"},\"password\":{\"type\":\"keyword\"},\"channel_name\":{\"type\":\"text\"}}}}"
Bash

curl -X PUT "http://192.168.56.30:9200/active_alarms" -H "Content-Type: application/json" -d "{\"mappings\":{\"properties\":{\"@timestamp\":{\"type\":\"date\"},\"alarm_id\":{\"type\":\"keyword\"},\"source\":{\"type\":\"keyword\"},\"server_ip\":{\"type\":\"ip\"},\"message\":{\"type\":\"text\"},\"severity\":{\"type\":\"keyword\"},\"channel_name\":{\"type\":\"keyword\"},\"device_name\":{\"type\":\"keyword\"},\"group_id\":{\"type\":\"keyword\"}}}}"
Bash

curl -X PUT "http://192.168.56.30:9200/historical_alarms" -H "Content-Type: application/json" -d "{\"mappings\":{\"properties\":{\"@timestamp\":{\"type\":\"date\"},\"alarm_id\":{\"type\":\"keyword\"},\"source\":{\"type\":\"keyword\"},\"server_ip\":{\"type\":\"ip\"},\"message\":{\"type\":\"text\"},\"severity\":{\"type\":\"keyword\"},\"channel_name\":{\"type\":\"keyword\"},\"device_name\":{\"type\":\"keyword\"},\"group_id\":{\"type\":\"keyword\"}}}}"
Get Index Schema 🧐
To retrieve the mapping (schema) for a specific index, use the following curl command:

Bash

curl -X GET "http://192.168.56.30:9200/historical_alarms?pretty"
Get Index Document 📜
To retrieve documents from an index (e.g., to see active alarms), use the following curl command. This will fetch the top 10 documents by default:

Bash

curl -X GET "http://192.168.56.30:9200/active_alarms/_search?pretty"
