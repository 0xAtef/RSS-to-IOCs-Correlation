import os
import re
import logging
import requests
from io import StringIO
from dotenv import load_dotenv
import csv

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
if not MISP_BASE_URL or not MISP_API_KEY:
    logging.critical("MISP_BASE_URL and MISP_API_KEY must be set in .env")
    raise ValueError("MISP_BASE_URL and MISP_API_KEY must be set in .env")

# -----------------------------------------------------------------------------
# CSV source and fetch
# -----------------------------------------------------------------------------
CSV_URL = (
    "https://raw.githubusercontent.com/0xAtef/RSS-to-IOCs-Correlation/"
    "main/misp_feed/feed.csv"
)

def fetch_csv_data(url):
    try:
        resp = requests.get(url, verify=False)
        resp.raise_for_status()
        logging.info("Fetched CSV data successfully")
        return resp.text
    except requests.RequestException as e:
        logging.critical(f"Failed to fetch CSV data: {e}")
        raise

# -----------------------------------------------------------------------------
# Normalize CSV
# -----------------------------------------------------------------------------
def normalize_data(csv_text):
    reader = csv.DictReader(StringIO(csv_text))
    events = {}
    for row in reader:
        info = row.get('info', '').strip()
        if not info:
            logging.warning("Skipping row: Missing 'info' field")
            continue
        events.setdefault(info, []).append(row)
    logging.info(f"Normalized data into {len(events)} events")
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
# Create events using requests
# -----------------------------------------------------------------------------
def create_events(events):
    headers = {
        "Authorization": MISP_API_KEY,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    for info, rows in events.items():
        logging.info(f"Processing event with info: '{info}'")

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
            "tags": []  # Initialize the tags field
        }

        # Add attributes
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
            else:
                logging.warning(f"Skipping invalid attribute: {row}")

        # Add tags
        for row in rows:
            if 'tag' in row and row['tag'].strip():
                tags = [tag.strip() for tag in row['tag'].split(';') if tag.strip()]
                event_payload["tags"].extend(tags)

        # Remove duplicate tags
        event_payload["tags"] = list(set(event_payload["tags"]))

        # Send POST request to create event
        try:
            logging.info(f"Creating event: '{sanitized_info}'")
            response = requests.post(
                f"{MISP_BASE_URL}/events/add",
                headers=headers,
                json=event_payload,
                verify=MISP_VERIFY_SSL,
                allow_redirects=False  # Disable automatic redirects
            )

            if response.status_code == 200:
                logging.info(f"Event created successfully: '{sanitized_info}'")
            elif response.status_code in (301, 302):
                logging.warning(f"Redirect received for event '{sanitized_info}': {response.headers.get('Location')}")
            else:
                logging.error(f"Failed to create event '{sanitized_info}': {response.status_code} {response.text}")

        except Exception as e:
            logging.error(f"Exception occurred while creating event '{sanitized_info}': {e}")

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
if __name__ == '__main__':
    try:
        csv_text = fetch_csv_data(CSV_URL)
        events = normalize_data(csv_text)
        create_events(events)
        logging.info("Script finished successfully")
    except Exception as e:
        logging.critical(f"Script terminated due to an error: {e}")