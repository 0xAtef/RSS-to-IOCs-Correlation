import json
import re

# Load the seen IOCs from the JSON file
with open("D:\\Script\\MyGitHub\\RSS-to-IOCs-Correlation\\output\\seen_iocs.json", "r") as f:
    seen_iocs = json.load(f)

# Define a regex pattern to identify domains or general URLs
whitelist_pattern = re.compile(
    r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$|^(?:https?://)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}/?$"
)

# Extract whitelist candidates
whitelist_candidates = [ioc for ioc in seen_iocs if whitelist_pattern.match(ioc)]

# Save the whitelist candidates to a file
with open("whitelist.json", "w") as f:
    json.dump(whitelist_candidates, f, indent=2)

print("Whitelist candidates extracted and saved to whitelist.json")