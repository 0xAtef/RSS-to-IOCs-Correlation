import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from pymisp import PyMISP, MISPEvent
import csv
import requests
from io import StringIO
from dotenv import load_dotenv
import os
import re

# -----------------------------------------------------------------------------
# 1) Load env, validate, init PyMISP
# -----------------------------------------------------------------------------
load_dotenv()

MISP_BASE_URL = os.getenv("MISP_BASE_URL")
MISP_API_KEY = os.getenv("MISP_API_KEY")
MISP_VERIFY_SSL = os.getenv("MISP_VERIFY_SSL", "true").lower() == "true"

if not MISP_BASE_URL or not MISP_API_KEY:
    raise ValueError("MISP configuration is missing. Check your .env")

misp = PyMISP(MISP_BASE_URL, MISP_API_KEY, ssl=False)  # Disable SSL for local testing

# -----------------------------------------------------------------------------
# 2) Fetch CSV, build events
# -----------------------------------------------------------------------------
csv_url = (
    "https://raw.githubusercontent.com/"
    "0xAtef/RSS-to-IOCs-Correlation/refs/heads/"
    "main/misp_feed/feed.csv"
)
resp = requests.get(csv_url)
resp.raise_for_status()

reader = csv.DictReader(StringIO(resp.text))
events = {}

for row in reader:
    # Validate the 'info' field
    if not row.get('info') or not row['info'].strip():
        print(f"Skipping row due to missing or empty 'info' field: {row}")
        continue

    # Sanitize and truncate the 'info' field
    sanitized_info = row['info'].strip().replace("\n", " ").replace("\r", "").replace("\t", "")
    sanitized_info = re.sub(r'[^\w\s\-.,\'"]', '', sanitized_info)  # Remove special characters
    sanitized_info = sanitized_info[:250]  # Truncate to 250 characters
    if not sanitized_info:
        print(f"Skipping row due to sanitized 'info' field being empty: {row}")
        continue

    # Make sure we always set row['info'] into our Event
    key = f"{sanitized_info}|{row['date']}"
    if key not in events:
        e = MISPEvent()
        e.info = sanitized_info  # Set the sanitized info field
        e.date = row['date']
        e.threat_level_id = row['threat_level_id']
        e.analysis = row['analysis']
        events[key] = e

    e = events[key]

    # Normalize attribute type
    atype = row['attribute_type']
    attribute_value = row['attribute_value'].strip()

    # Validate domain attributes
    if atype == "domain" and not re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', attribute_value):
        print(f"Skipping invalid domain attribute: {attribute_value}")
        continue

    # Add the main IOC attribute
    e.add_attribute(
        type=atype,
        category=row['attribute_category'],
        value=attribute_value,
        to_ids=(row['to_ids'] == 'True'),
        comment=row.get('comment', ''),
        timestamp=row.get('attribute_timestamp') or None
    )

    # Tags
    for tag in filter(None, (t.strip() for t in row.get('tag', '').split(';'))):
        e.add_tag(tag)

    # Contextual text fields
    for field, cat in [
        ('actors', 'Attribution'),
        ('malware', 'Artifacts dropped'),
        ('mitre_techniques', 'External analysis'),
        ('cves', 'External analysis'),
        ('tools', 'External analysis'),
        ('campaigns', 'Attribution'),
    ]:
        for val in filter(None, (i.strip() for i in row.get(field, '').split(';'))):
            e.add_attribute(
                type='text',
                category=cat,
                value=val,
                to_ids=False,
                comment=f"Added from {field}"
            )

# -----------------------------------------------------------------------------
# 3) Push to MISP, printing out the JSON to verify "info" is present
# -----------------------------------------------------------------------------
for e in events.values():
    print(f">>> SENDING: Event Info: {e.info[:50]}...")
    print(f"Full Event Payload: {e.to_json()}")  # Debug: Print full event details

    # Ensure the 'info' field is set and valid
    if not e.info or not e.info.strip():
        print(f"Error: Event with empty 'info' field detected. Adding fallback value.")
        e.info = "Default Info: Missing or Undefined"

    try:
        result = misp.add_event(e, pythonify=True)  # Directly pass the MISPEvent object
        print(f"Pushed event: {e.info} -> id={getattr(result, 'id', result)}")
    except Exception as ex:
        print(f"Failed to push event: {e.info}. Error: {ex}")