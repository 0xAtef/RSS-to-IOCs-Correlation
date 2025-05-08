import json
import os

class ConfigLoader:
    @staticmethod
    def load_config(config_path="config/config.json"):
        """
        Load and validate the configuration file.
        :param config_path: Path to the config.json file.
        :return: Parsed configuration as a dictionary.
        """
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Configuration file not found at {config_path}.")

        with open(config_path, "r") as f:
            config = json.load(f)

        # Perform basic validation
        required_keys = ["org_name", "org_uuid", "feed_urls"]
        for key in required_keys:
            if key not in config:
                raise KeyError(f"Missing required key in config: {key}")

        return config