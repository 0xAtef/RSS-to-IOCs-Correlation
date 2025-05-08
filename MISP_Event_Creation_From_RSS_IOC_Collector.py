from pymisp import PyMISP, MISPEvent
import csv
import requests
from io import StringIO
from dotenv import load_dotenv
import os

# -----------------------------------------------------------------------------
# 1) Load env, validate, init PyMISP
# -----------------------------------------------------------------------------
load_dotenv()

MISP_BASE_URL   = os.getenv("MISP_BASE_URL")
MISP_API_KEY    = os.getenv("MISP_API_KEY")
MISP_VERIFY_SSL = os.getenv("MISP_VERIFY_SSL", "true").lower() == "true"

if not MISP_BASE_URL or not MISP_API_KEY:
    raise ValueError("MISP configuration is missing. Check your .env")

misp = PyMISP(MISP_BASE_URL, MISP_API_KEY, ssl=MISP_VERIFY_SSL)

# -----------------------------------------------------------------------------
# 2) Monkey-patch add_event to use JSON bodies
# -----------------------------------------------------------------------------
def add_event_json(self, event, pythonify=False, metadata=False):
    """
    event must be a dict {'Event': { ... }}
    This sends it as JSON so MISP sees the 'info' field, etc.
    """
    session = requests.Session()  # Manually create a session
    session.headers.update({'Authorization': self.key, 'Accept': 'application/json'})
    resp = session.post(self.url, json=event, verify=self.ssl)
    return self._check_response(resp, pythonify, metadata)

# Replace the method on PyMISP
PyMISP.add_event = add_event_json

# -----------------------------------------------------------------------------
# 3) Fetch CSV, build events
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
    # Make sure we always set row['info'] into our Event
    key = f"{row['info']}|{row['date']}"
    if key not in events:
        e = MISPEvent()
        e.info            = row['info']            # <-- required!
        e.date            = row['date']
        e.threat_level_id = row['threat_level_id']
        e.analysis        = row['analysis']
        events[key] = e

    e = events[key]

    # Normalize attribute type
    atype = row['attribute_type']
    if atype == 'cve':
        atype = 'vulnerability'
    elif atype == 'ip':
        atype = 'ip-src'

    # Add the main IOC attribute
    e.add_attribute(
        type=atype,
        category=row['attribute_category'],
        value=row['attribute_value'],
        to_ids=(row['to_ids'] == 'True'),
        comment=row.get('comment', ''),
        timestamp=row.get('attribute_timestamp') or None
    )

    # Tags
    for tag in filter(None, (t.strip() for t in row.get('tag', '').split(';'))):
        e.add_tag(tag)

    # Contextual text fields
    for field, cat in [
        ('actors',           'Attribution'),
        ('malware',          'Artifacts dropped'),
        ('mitre_techniques', 'External analysis'),
        ('cves',             'External analysis'),
        ('tools',            'External analysis'),
        ('campaigns',        'Attribution'),
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
# 4) Push to MISP, printing out the JSON to verify "info" is present
# -----------------------------------------------------------------------------
for e in events.values():
    json_payload = e.to_json()   # this is already a str: '{"Event": { … }}'
    print(">>> SENDING:", json_payload[:200], "…")
    result = misp.add_event(json_payload, pythonify=True)
    print(f"Pushed event: {e.info} -> id={getattr(result, 'id', result)}")