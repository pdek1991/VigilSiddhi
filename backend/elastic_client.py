import json
import yaml
from elasticsearch import Elasticsearch

class ElasticManager:
    def __init__(self, hosts=["http://192.168.56.30:9200"]):
        """
        Initializes the Elasticsearch client.
        :param hosts: List of Elasticsearch node URLs.
        """
        self.client = Elasticsearch(hosts)
        if not self.client.ping():
            raise ConnectionError("Could not connect to Elasticsearch")
        print("Successfully connected to Elasticsearch.")

    def get_client(self):
        return self.client

    def load_initial_configs(self, config_paths):
        """
        Loads initial configurations from files into Elasticsearch.
        This is a one-time operation.
        """
        print("Starting initial configuration load into Elasticsearch...")

        # Load channel_ilo_config.json
        with open(config_paths['channel'], 'r') as f:
            channel_data = json.load(f)
            for item in channel_data:
                self.client.index(index='channel_config', id=item['channel_id'], body=item, refresh=True)
        print(f"Loaded {len(channel_data)} documents into 'channel_config' index.")

        # Load global_ilo_config.json
        with open(config_paths['global'], 'r') as f:
            global_data = json.load(f)
            for item in global_data:
                self.client.index(index='global_config', id=item['id'], body=item, refresh=True)
        print(f"Loaded {len(global_data)} documents into 'global_config' index.")

        # Load windows_config.yaml
        with open(config_paths['windows'], 'r') as f:
            windows_data = yaml.safe_load(f)
            for host in windows_data.get('windows_hosts', []):
                self.client.index(index='windows_config', id=host['name'], body=host, refresh=True)
        print(f"Loaded {len(windows_data.get('windows_hosts', []))} documents into 'windows_config' index.")
        
        print("Initial configuration load complete.")

if __name__ == '__main__':
    # --- ONE-TIME EXECUTION TO LOAD CONFIGS ---
    # Ensure your Elasticsearch is running before executing this.
    # Replace with the actual paths to your config files.
    
    config_file_paths = {
        'channel': '../initial_configs/channel_ilo_config.json',
        'global': '../initial_configs/global_ilo_config.json',
        'windows': '../initial_configs/windows_config.yaml'
    }
    
    try:
        es_manager = ElasticManager(hosts=["http://192.168.56.30:9200"])
        es_manager.load_initial_configs(config_file_paths)
    except FileNotFoundError as e:
        print(f"Error: Configuration file not found. {e}")
    except Exception as e:
        print(f"An error occurred: {e}")