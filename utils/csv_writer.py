import csv
import logging
from utils.translator import translate_to_english

def write_csv_feed(all_records, csv_path, org_uuid, org_name, cfg):
    """
    Write the collected IOCs and enrichment data to a CSV file.
    Translate non-English text to English before writing.
    """
    fieldnames = [
        "uuid", "info", "date", "threat_level_id", "analysis",
        "orgc_uuid", "orgc_name", "tag", "attribute_category", "attribute_type",
        "attribute_value", "to_ids", "comment", "attribute_timestamp",
        "actors", "malware", "mitre_techniques", "cves", "tools", "campaigns"
    ]

    try:
        with open(csv_path, "w", newline="", encoding="utf-8") as csvf:
            w = csv.DictWriter(csvf, fieldnames=fieldnames)
            w.writeheader()

            for rec in all_records:
                if not rec.get("id") or not rec.get("title"):
                    logging.warning(f"Skipping record with missing required fields: {rec}")
                    continue

                row = {
                    "uuid": rec.get("id", ""),
                    "info": translate_to_english(rec.get("title", "No Title")),
                    "date": rec.get("published", "").split("T")[0] if rec.get("published") else "",
                    "threat_level_id": cfg.get("misp_threat_level_id", 4),
                    "analysis": cfg.get("misp_analysis", 0),
                    "orgc_uuid": org_uuid,
                    "orgc_name": org_name,
                    "tag": ";".join(rec.get("tags", [])),
                    "attribute_category": "External analysis",
                    "attribute_type": "",  # Ensure this is populated elsewhere
                    "attribute_value": "",  # Ensure this is populated elsewhere
                    "to_ids": "True",
                    "comment": translate_to_english(f"Extracted from: {rec.get('source', 'Unknown Source')}"),
                    "attribute_timestamp": "",  # Ensure this is populated elsewhere
                    "actors": ";".join(rec.get("enrichment", {}).get("actors", [])),
                    "malware": ";".join(rec.get("enrichment", {}).get("malware", [])),
                    "mitre_techniques": ";".join(rec.get("enrichment", {}).get("mitre_techniques", [])),
                    "cves": ";".join(rec.get("enrichment", {}).get("cves", [])),
                    "tools": ";".join(rec.get("enrichment", {}).get("tools", [])),
                    "campaigns": ";".join(rec.get("enrichment", {}).get("campaigns", []))
                }

                for typ, vals in rec["iocs"].items():
                    for val in vals:
                        row["attribute_type"] = typ.rstrip("s")
                        row["attribute_value"] = val
                        row["attribute_timestamp"] = rec.get("timestamp", "")

                        w.writerow(row)

        logging.info(f"✅ Wrote MISP-compatible CSV feed to {csv_path}")
    except Exception as e:
        logging.error(f"Failed to write CSV feed: {e}")