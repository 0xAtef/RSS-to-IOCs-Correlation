from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute
import csv

misp = ExpandedPyMISP('https://127.0.0.1', 'VIPPqM2LUwxsNfaLnzz0Ju2S2QCPqHI8BELemWgA', ssl=False)

# Open and read the CSV file
with open('D:\\Script\\MyGitHub\\RSS-to-IOCs-Correlation\\misp_feed\\feed.csv', newline='', encoding='utf-8') as csvfile:
    reader = csv.DictReader(csvfile)
    # Print the headers to check column names
    print(reader.fieldnames)
    for row in reader:
        print(row)


    # Loop through each row in the CSV to build events and attributes
    for row in reader:
        uuid = row['uuid']  # Use the correct key for the UUID

        # Create new event if UUID is not already in events dictionary
        if uuid not in events:
            event = MISPEvent()
            event.uuid = uuid
            event.info = row['info']
            event.date = row['date']
            event.threat_level_id = row['threat_level_id']
            event.analysis = row['analysis']
            event.orgc_uuid = row['orgc_uuid']
            event.orgc_name = row['orgc_name']

            # Add tags to the event (if any tags are present in the CSV)
            tags = row['tag'].split(';')  # Assuming multiple tags are separated by a semicolon
            for tag in tags:
                event.add_tag(tag.strip())  # Strip any extra spaces from tags

            events[uuid] = event
        
        # Create attribute for the event
        attr = MISPAttribute()
        attr.type = row['attribute_type']
        attr.category = row['attribute_category']
        attr.value = row['attribute_value']
        attr.to_ids = row['to_ids'] == 'True'  # Convert to boolean
        attr.comment = row['comment']
        
        # Add attribute to the respective event
        events[uuid].add_attribute(**attr)

# Push the events to MISP
for event in events.values():
    misp.add_event(event)
