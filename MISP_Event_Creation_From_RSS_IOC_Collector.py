from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute
import csv
import requests
from io import StringIO

# Initialize MISP instance
misp = ExpandedPyMISP('https://127.0.0.1', 'VIPPqM2LUwxsNfaLnzz0Ju2S2QCPqHI8BELemWgA', ssl=False)

# URL of the CSV file
csv_url = 'https://raw.githubusercontent.com/0xAtef/RSS-to-IOCs-Correlation/main/misp_feed/feed.csv'

# Fetch the CSV file from the URL
response = requests.get(csv_url)
response.raise_for_status()  # Raise an error if the request fails

# Parse the CSV content
csv_content = StringIO(response.text)

# === INITIALIZE EVENTS DICTIONARY ===
events = {}

# === READ AND PARSE CSV ===
reader = csv.DictReader(csv_content)
for row in reader:
    uuid = row['uuid']
    if uuid not in events:
        event = MISPEvent()
        event.uuid = uuid
        event.info = row['info']
        event.date = row['date']
        event.threat_level_id = row['threat_level_id']
        event.analysis = row['analysis']
        event.orgc_uuid = row['orgc_uuid']
        event.orgc_name = row['orgc_name']
        events[uuid] = event

    # === Create Attribute ===
    attr = MISPAttribute()
    attr_type = row['attribute_type']

    # Map unsupported types to valid MISP types
    if attr_type == 'cve':
        attr_type = 'vulnerability'
    elif attr_type == 'ip':
        # Default to 'ip-src' if no context is provided
        attr_type = 'ip-src'

    attr.type = attr_type
    attr.category = row['attribute_category']
    attr.value = row['attribute_value']
    attr.to_ids = row['to_ids'] == 'True'
    attr.comment = row['comment']

    # Optional timestamp
    if row.get('attribute_timestamp'):
        attr.timestamp = row['attribute_timestamp']

    events[uuid].add_attribute(**attr)

    # === Add Tags if Present ===
    if 'tag' in row and row['tag']:
        for t in row['tag'].split(';'):
            if t.strip():
                events[uuid].add_tag(t.strip())

# === PUSH EVENTS TO MISP ===
for event in events.values():
    result = misp.add_event(event)
    print(f"Pushed event: {event.info} -> {result}")