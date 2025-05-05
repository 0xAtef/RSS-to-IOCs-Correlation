import json
import os
import sys
from datetime import datetime
import uuid

def generate_manifest(event_uuid: str, timestamp: int) -> dict:
    return {
        "Event": {
            "uuid": event_uuid,
            "timestamp": timestamp
        }
    }

def main(input_file: str, output_base_dir: str):
    with open(input_file, 'r') as f:
        event_data = json.load(f)

    # Ensure base output directory exists
    os.makedirs(output_base_dir, exist_ok=True)

    # Use UUID or timestamp for folder name
    event_uuid = event_data.get('uuid') or str(uuid.uuid4())
    timestamp = int(datetime.utcnow().timestamp())
    event_dir = os.path.join(output_base_dir, event_uuid)import os
import json
import uuid
from datetime import datetime

def main(input_file: str, output_base_dir: str):
    # Load the input data
    with open(input_file, 'r') as f:
        event_data = json.load(f)

    # If the data is a list, assume it's a collection of events and process the first one
    if isinstance(event_data, list):
        event_data = event_data[0]  # Take the first event from the list
    
    # Now event_data should be a dictionary, so we can call .get()
    event_uuid = event_data.get('uuid') or str(uuid.uuid4())
    timestamp = int(datetime.utcnow().timestamp())
    
    # Create event directory
    event_dir = os.path.join(output_base_dir, event_uuid)
    os.makedirs(event_dir, exist_ok=True)

    # Save the event JSON to a file
    event_path = os.path.join(event_dir, "event.json")
    with open(event_path, 'w') as f:
        json.dump(event_data, f, indent=2)

    # Create and save a manifest
    manifest_data = {
        "Event": {
            "uuid": event_uuid,
            "timestamp": timestamp
        }
    }
    manifest_path = os.path.join(event_dir, "manifest.json")
    with open(manifest_path, 'w') as f:
        json.dump(manifest_data, f, indent=2)

    print(f"Saved event to {event_path}")
    print(f"Saved manifest to {manifest_path}")

# CLI execution block
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python misp_push.py <input_json> <output_base_dir>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])

    os.makedirs(event_dir, exist_ok=True)

    # Save event.json
    event_path = os.path.join(event_dir, "event.json")
    with open(event_path, 'w') as f:
        json.dump(event_data, f, indent=2)

    # Save manifest.json
    manifest_data = generate_manifest(event_uuid, timestamp)
    manifest_path = os.path.join(event_dir, "manifest.json")
    with open(manifest_path, 'w') as f:
        json.dump(manifest_data, f, indent=2)

    print(f"Saved event to {event_path}")
    print(f"Saved manifest to {manifest_path}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python misp_push.py <input_json> <output_base_dir>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
