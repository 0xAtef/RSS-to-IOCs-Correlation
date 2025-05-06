from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute
import csv

misp = ExpandedPyMISP('https://127.0.0.1', 'VIPPqM2LUwxsNfaLnzz0Ju2S2QCPqHI8BELemWgA', ssl=False)
csv_path = 'D:\\Script\\MyGitHub\\RSS-to-IOCs-Correlation\\misp_feed\\feed.csv'
# === INITIALIZE EVENTS DICTIONARY ===
events = {}

# === READ AND PARSE CSV ===
with open(csv_path, newline='', encoding='utf-8') as csvfile:
    reader = csv.DictReader(csvfile)
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
        attr.type = row['attribute_type']
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