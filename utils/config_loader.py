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

        try:
            with open(config_path, "r") as f:
                config = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to decode JSON config: {e}")

        # Perform basic validation
        required_keys = ["org_name", "org_uuid", "feed_urls"]
        for key in required_keys:
            if key not in config:
                raise KeyError(f"Missing required key in config: {key}")

        # Add default values for optional keys
        config.setdefault("user_agent", "Mozilla/5.0")
        config.setdefault("request_timeout", 10)

        return config