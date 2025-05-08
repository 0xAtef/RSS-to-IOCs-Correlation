import json

# File paths
seen_iocs_path = "d:/Script/MyGitHub/RSS-to-IOCs-Correlation/output/seen_iocs.json"
config_path = "d:/Script/MyGitHub/RSS-to-IOCs-Correlation/config/config.json"

# Function to clean seen IOCs based on the whitelist (checks if the IOC contains any domain from the whitelist)
def clean_iocs_with_whitelist(iocs, whitelist):
    cleaned_iocs = []
    for ioc in iocs:
        # Check if the IOC contains any domain in the whitelist
        if not any(domain in ioc for domain in whitelist):
            cleaned_iocs.append(ioc)
    return cleaned_iocs

# Load seen_iocs.json
with open(seen_iocs_path, "r") as f:
    seen_iocs = json.load(f)

# Load config.json
with open(config_path, "r") as f:
    config = json.load(f)

# Extract the global whitelist from whitelist_by_feed
global_whitelist = config.get("whitelist_by_feed", {}).get("*", [])

# Clean seen_iocs.json using the global whitelist
cleaned_seen_iocs = clean_iocs_with_whitelist(seen_iocs, global_whitelist)

# Save the cleaned seen_iocs.json
with open(seen_iocs_path, "w") as f:
    json.dump(cleaned_seen_iocs, f, indent=2)
print(f"Processed seen_iocs.json: Removed {len(seen_iocs) - len(cleaned_seen_iocs)} entries based on the whitelist.")

# Update whitelist_by_feed in config.json (optional, if needed)
if "whitelist_by_feed" in config:
    for feed, whitelist in config["whitelist_by_feed"].items():
        config["whitelist_by_feed"][feed] = list(set(whitelist))  # Ensure unique entries in the whitelist

with open(config_path, "w") as f:
    json.dump(config, f, indent=2)
print("Processed whitelist_by_feed in config.json.")