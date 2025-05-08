import os
import re
import logging
import requests
from io import StringIO
from dotenv import load_dotenv
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed

# -----------------------------------------------------------------------------
# Setup logging
# -----------------------------------------------------------------------------
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    filename="misp_event_creation.log",
    level=log_level,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
console = logging.StreamHandler()
console.setLevel(logging.getLevelName(log_level))
console.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logging.getLogger().addHandler(console)
logging.info("Starting MISP Event Creation Script")

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings()

# -----------------------------------------------------------------------------
# Load environment variables
# -----------------------------------------------------------------------------
load_dotenv()
MISP_BASE_URL = os.getenv("MISP_BASE_URL")
MISP_API_KEY = os.getenv("MISP_API_KEY")
MISP_VERIFY_SSL = os.getenv("MISP_VERIFY_SSL", "true").lower() == "true"
MAX_THREADS = int(os.getenv("MAX_THREADS", 5))

if not MISP_BASE_URL or not MISP_API_KEY:
    logging.critical("MISP_BASE_URL and MISP_API_KEY must be set in .env")
    raise ValueError("MISP_BASE_URL and MISP_API_KEY must be set in .env")

# -----------------------------------------------------------------------------
# CSV source and fetch
# -----------------------------------------------------------------------------
DEFAULT_CSV_URL = "https://raw.githubusercontent.com/0xAtef/RSS-to-IOCs-Correlation/main/misp_feed/feed.csv"
ALT_CSV_URL = "https://raw.githubusercontent.com/0xAtef/RSS-to-IOCs-Correlation/refs/heads/main/misp_feed/feed.csv"

CSV_URL = DEFAULT_CSV_URL if DEFAULT_CSV_URL in os.getenv("CSV_URL", DEFAULT_CSV_URL) else ALT_CSV_URL

def fetch_csv_data(url):
    """Fetch CSV data from the given URL."""
    try:
        resp = requests.get(url, verify=False)
        resp.raise_for_status()
        logging.info(f"Fetched CSV data from {url} successfully")
        return resp.text
    except requests.RequestException as e:
        logging.critical(f"Failed to fetch CSV data: {e}")
        raise

# -----------------------------------------------------------------------------
# Normalize CSV
# -----------------------------------------------------------------------------
def normalize_data(csv_text):
    """Parse and normalize the CSV data into events."""
    reader = csv.DictReader(StringIO(csv_text))
    total_rows = 0
    events = {}
    for row in reader:
        total_rows += 1
        info = row.get('info', '').strip()
        if not info:
            logging.warning("Skipping row: Missing 'info' field")
            continue
        events.setdefault(info, []).append(row)
    logging.info(f"Total rows in CSV: {total_rows}")
    logging.info(f"Total normalized events: {len(events)}")
    return events

# -----------------------------------------------------------------------------
# Sanitize and validate the info field
# -----------------------------------------------------------------------------
def sanitize_info(info):
    """Sanitize the 'info' field and ensure UTF-8 encoding."""
    sanitized_info = info.strip()
    sanitized_info = re.sub(r'[^\w\s\-.,\'"]', '', sanitized_info)  # Remove invalid characters
    sanitized_info = sanitized_info[:255]  # Truncate to 255 characters (MISP limit)
    try:
        sanitized_info = sanitized_info.encode('utf-8').decode('utf-8')  # Ensure UTF-8 encoding
    except UnicodeDecodeError:
        logging.warning(f"Failed to encode info field to UTF-8: {info}")
        sanitized_info = "Default Info: Event Title Missing"
    return sanitized_info or "Default Info: Event Title Missing"  # Use fallback if empty

# -----------------------------------------------------------------------------
# Add tags to an event
# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------
# Retrieve or create a tag
# -----------------------------------------------------------------------------
def get_or_create_tag(tag_name):
    """Retrieve the tag ID for a given tag name or create the tag if it does not exist."""
    headers = {
        "Authorization": MISP_API_KEY,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    # Search for the tag
    try:
        response = requests.get(
            f"{MISP_BASE_URL}/tags",
            headers=headers,
            verify=MISP_VERIFY_SSL
        )
        if response.status_code == 200:
            tags = response.json().get('Tag', [])
            for tag in tags:
                if tag.get('name') == tag_name:
                    return tag.get('id')
        else:
            logging.error(f"Failed to retrieve tags: {response.status_code} {response.text}")

    except Exception as e:
        logging.error(f"Exception occurred while retrieving tags: {e}")

    # Create the tag if not found
    payload = {"name": tag_name}
    try:
        response = requests.post(
            f"{MISP_BASE_URL}/tags/add",
            headers=headers,
            json=payload,
            verify=MISP_VERIFY_SSL
        )
        if response.status_code == 200:
            tag_id = response.json().get('Tag', {}).get('id')
            logging.info(f"Created new tag '{tag_name}' with ID {tag_id}")
            return tag_id
        else:
            logging.error(f"Failed to create tag '{tag_name}': {response.status_code} {response.text}")

    except Exception as e:
        logging.error(f"Exception occurred while creating tag '{tag_name}': {e}")

    return None

# -----------------------------------------------------------------------------
# Add tags to an event
# -----------------------------------------------------------------------------
def add_tags(event_id, tags):
    """Add tags to an existing MISP event."""
    headers = {
        "Authorization": MISP_API_KEY,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    for tag in tags:
        tag_id = get_or_create_tag(tag)
        if not tag_id:
            logging.error(f"Skipping tag '{tag}' due to failure in retrieval or creation.")
            continue

        try:
            # Correct endpoint format
            response = requests.post(
                f"{MISP_BASE_URL}/events/addTag/{event_id}/{tag_id}/local:true",
                headers=headers,
                verify=MISP_VERIFY_SSL
            )
            if response.status_code == 200:
                logging.info(f"Successfully added tag '{tag}' to event ID {event_id}")
            else:
                logging.error(f"Failed to add tag '{tag}' to event ID {event_id}: {response.status_code} {response.text}")
        except Exception as e:
            logging.error(f"Exception occurred while adding tag '{tag}' to event ID {event_id}: {e}")
# -----------------------------------------------------------------------------
# Create event in MISP
# -----------------------------------------------------------------------------
def create_event(info, rows):
    """Create a MISP event from a normalized event dictionary."""
    headers = {
        "Authorization": MISP_API_KEY,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    # Sanitize and validate the 'info' field
    sanitized_info = sanitize_info(info)

    # Build event payload
    event_payload = {
        "info": sanitized_info,
        "date": rows[0].get('date'),
        "threat_level_id": int(rows[0].get('threat_level_id', 3)),
        "analysis": int(rows[0].get('analysis', 0)),
        "distribution": int(rows[0].get('distribution', 0)),
        "Attribute": [],
        "tags": []
    }

    # Add attributes
    attributes_added = 0
    for row in rows:
        at = row.get('attribute_type', '').strip()
        val = row.get('attribute_value', '').strip()
        cat = row.get('attribute_category', '').strip()
        to_ids = row.get('to_ids', '').strip().lower() == 'true'
        comment = row.get('comment', '').strip() or None

        if at and val and cat:
            attribute = {
                "type": at,
                "category": cat,
                "value": val,
                "to_ids": to_ids,
                "comment": comment
            }
            event_payload["Attribute"].append(attribute)
            attributes_added += 1
        else:
            logging.warning(f"Skipping invalid attribute: {row}")

    # Extract CVEs
    cve_pattern = re.compile(r'\bCVE-\d{4}-\d{4,7}\b')
    for row in rows:
        if 'attribute_value' in row and cve_pattern.match(row['attribute_value']):
            cve_attribute = {
                "type": "vulnerability",
                "category": "External analysis",
                "value": row['attribute_value'],
                "to_ids": True,
                "comment": "Extracted CVE"
            }
            event_payload["Attribute"].append(cve_attribute)
            attributes_added += 1

    # Extract tags
    tags = []
    for row in rows:
        if 'tag' in row and row['tag'].strip():
            tags.extend([tag.strip() for tag in row['tag'].split(';') if tag.strip()])

    # Remove duplicate tags
    tags = list(set(tags))

    # Log the number of attributes and tags added
    logging.info(f"Event '{sanitized_info}': Added {attributes_added} attributes and {len(tags)} tags.")

    # Send POST request to create event
    try:
        response = requests.post(
            f"{MISP_BASE_URL}/events/add",
            headers=headers,
            json=event_payload,
            verify=MISP_VERIFY_SSL,
            allow_redirects=False
        )

        if response.status_code == 200:
            logging.info(f"Event created successfully: '{sanitized_info}'")
            event_id = response.json().get('Event', {}).get('id')
            if event_id:
                add_tags(event_id, tags)
        else:
            logging.error(f"Failed to create event '{sanitized_info}': {response.status_code} {response.text}")
    except Exception as e:
        logging.error(f"Exception occurred while creating event '{sanitized_info}': {e}")

# -----------------------------------------------------------------------------
# Process events with multi-threading
# -----------------------------------------------------------------------------
def process_events(events):
    """Process events using multi-threading for faster execution."""
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_event = {executor.submit(create_event, info, rows): info for info, rows in events.items()}

        for future in as_completed(future_to_event):
            info = future_to_event[future]
            try:
                future.result()
            except Exception as e:
                logging.error(f"Exception occurred while processing event '{info}': {e}")

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
if __name__ == '__main__':
    try:
        csv_text = fetch_csv_data(CSV_URL)
        events = normalize_data(csv_text)
        process_events(events)
        logging.info("Script finished successfully")
    except Exception as e:
        logging.critical(f"Script terminated due to an error: {e}")