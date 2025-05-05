import json
import os
import sys
from glob import glob
from datetime import datetime
import uuid

# Base URL for raw.githubusercontent access to event manifests
RAW_BASE = "https://raw.githubusercontent.com/0xAtef/RSS-to-IOCs-Correlation/main/misp_feed/events"

def generate_manifest(event_uuid: str, timestamp: int) -> dict:
    return {
        "Event": {
            "uuid": event_uuid,
            "timestamp": timestamp
        }
    }

def rebuild_root_manifest(output_base_dir: str):
    """
    Scans output_base_dir/events/*/manifest.json and writes a root manifest.json
    listing each event's uuid and its raw URL.
    """
    events_dir = os.path.join(output_base_dir, "events")
    entries = []
    for manifest_path in glob(os.path.join(events_dir, "*/manifest.json")):
        uuid_dir = os.path.basename(os.path.dirname(manifest_path))
        url = f"{RAW_BASE}/{uuid_dir}/manifest.json"
        entries.append({"uuid": uuid_dir, "url": url})
    root_manifest = {"events": entries}
    with open(os.path.join(output_base_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(root_manifest, f, indent=2)

def main(input_file: str, output_base_dir: str):
    # Load the input JSON (could be a list or dict)
    with open(input_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # If it's a list, take the first element
    if isinstance(data, list):
        data = data[0]

    # Ensure base output directory and events/ exist
    os.makedirs(output_base_dir, exist_ok=True)
    events_root = os.path.join(output_base_dir, "events")
    os.makedirs(events_root, exist_ok=True)

    # Determine UUID and timestamp
    event_uuid = data.get('uuid') or str(uuid.uuid4())
    timestamp = int(datetime.utcnow().timestamp())

    # Create folder for this event
    event_dir = os.path.join(events_root, event_uuid)
    os.makedirs(event_dir, exist_ok=True)

    # Write event.json
    event_path = os.path.join(event_dir, "event.json")
    with open(event_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

    # Write manifest.json for this event
    manifest_data = generate_manifest(event_uuid, timestamp)
    manifest_path = os.path.join(event_dir, "manifest.json")
    with open(manifest_path, 'w', encoding='utf-8') as f:
        json.dump(manifest_data, f, indent=2)

    print(f"Saved event to {event_path}")
    print(f"Saved manifest to {manifest_path}")

    # Rebuild the root manifest.json
    rebuild_root_manifest(output_base_dir)
    print(f"Rebuilt root manifest at {os.path.join(output_base_dir, 'manifest.json')}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python misp_push.py <input_json> <output_base_dir>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
