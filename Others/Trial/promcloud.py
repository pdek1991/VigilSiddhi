import time
import random
import requests
from prometheus_client import CollectorRegistry, Gauge, generate_latest

# ----------------------------
# Configuration
# ----------------------------
USERNAME = "1788125"
PASSWORD = "glc_eyJvIjoiMTIxOTkwOCIsIm4iOiJwZGMtcGRlazE5OTEtZGVmYXVsdC12aWdpbHNpZGRoaSIsImsiOiJwQ0o3ODNnRkFEQzZyMDYzV0UzWTVKTDgiLCJtIjp7InIiOiJwcm9kLWFwLXNvdXRoLTEifX0="  # Replace with your Grafana Cloud API token
REMOTE_WRITE_URL = "https://prometheus-prod-43-prod-ap-south-1.grafana.net/api/prom/push"

# Generate 50 unique Sony channel names
CHANNEL_NAMES = [f"sony_channel_{i}" for i in range(1, 51)]

# Total data points per channel
DATA_POINTS = 100

# ----------------------------
# Function to generate metrics for a single point in time
# ----------------------------
def generate_metrics(channels):
    registry = CollectorRegistry()
    g_cnmargin = Gauge('channel_cnmargin', 'CN Margin of channel', ['channel'], registry=registry)
    g_system = Gauge('system_status', 'System status value', ['channel'], registry=registry)

    for channel in channels:
        cnmargin = round(random.uniform(6.0, 8.0), 2)
        system = random.randint(1, 5)
        g_cnmargin.labels(channel=channel).set(cnmargin)
        g_system.labels(channel=channel).set(system)

    return generate_latest(registry)

# ----------------------------
# Push metrics to Grafana Cloud
# ----------------------------
def push_metrics(data):
    headers = {
        'Content-Type': 'application/vnd.prometheus.prometheus',
    }

    response = requests.post(
        REMOTE_WRITE_URL,
        headers=headers,
        data=data,
        auth=(USERNAME, PASSWORD)
    )

    if response.status_code == 200:
        print("✅ Metrics pushed successfully")
    else:
        print(f"❌ Failed to push metrics: {response.status_code}")
        print(response.text)

# ----------------------------
# Main simulation loop
# ----------------------------
if __name__ == "__main__":
    for i in range(DATA_POINTS):
        print(f"📡 Sending data point {i+1}/{DATA_POINTS} for all channels")
        data = generate_metrics(CHANNEL_NAMES)
        push_metrics(data)
        time.sleep(1)  # Optional: simulate 1 second interval between points
