import json
import os
import hashlib
from datetime import datetime

def generate_misp_event(record):
    event = {
        "uuid": record["id"],
        "info": record["title"],
        "published": True,
        "date": record["published"][:10] if record["published"] else datetime.utcnow().strftime("%Y-%m-%d"),
        "Attribute": [],
        "Tag": [{"name": tag} for tag in record.get("tags", [])]
    }

    for ioc_type, iocs in record["iocs"].items():
        for ioc in iocs:
            event["Attribute"].append({
                "type": ioc_type.rstrip("s"),  # crude mapping
                "category": "Network activity",
                "value": ioc,
                "to_ids": True
            })

    return event

def write_misp_feed(records, output_path):
    if not records:
        return
    misp_feed = [generate_misp_event(r) for r in records]
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(misp_feed, f, indent=2, ensure_ascii=False)
    print(f"Wrote {len(misp_feed)} MISP events to {output_path}")