import csv
import logging
from utils.translator import translate_to_english

def write_csv_feed(all_records, csv_path, cfg, log_file=None):
    """
    Write the collected IOCs and enrichment data to a CSV file.
    Translate non-English text to English before writing.

    Args:
        all_records (list): List of dictionaries containing IOCs and enrichment data.
        csv_path (str): Path to the CSV file to write to.
        cfg (dict): Configuration dictionary with MISP-specific settings.
        log_file (str, optional): Path to the log file.
    """
    fieldnames = [
        "info", "date", "threat_level_id", "analysis",
        "tag", "attribute_category", "attribute_type",
        "attribute_value", "to_ids", "comment", "attribute_timestamp",
        "actors", "malware", "mitre_techniques", "cves", "tools", "campaigns"
    ]

    try:
        with open(csv_path, "w", newline="", encoding="utf-8") as csvf:
            writer = csv.DictWriter(csvf, fieldnames=fieldnames)
            writer.writeheader()

            for rec in all_records:
                # Skip records with missing required fields
                if not rec.get("id") or not rec.get("title"):
                    logging.warning(f"Skipping record with missing required fields: {rec}")
                    continue

                # Prepare the base row
                row = {
                    "info": translate_to_english(rec.get("title", "No Title")),
                    "date": rec.get("published", "").split("T")[0] if rec.get("published") else "",
                    "threat_level_id": cfg.get("misp_threat_level_id", 4),
                    "analysis": cfg.get("misp_analysis", 0),
                    "tag": ";".join(rec.get("tags", []) or []),
                    "attribute_category": "External analysis",
                    "attribute_type": "",  # Ensure this is populated elsewhere
                    "attribute_value": "",  # Ensure this is populated elsewhere
                    "to_ids": "True",
                    "comment": translate_to_english(f"Extracted from: {rec.get('source', 'Unknown Source')}"),
                    "attribute_timestamp": "",  # Ensure this is populated elsewhere
                    "actors": ";".join(rec.get("enrichment", {}).get("actors", []) or []),
                    "malware": ";".join(rec.get("enrichment", {}).get("malware", []) or []),
                    "mitre_techniques": ";".join(rec.get("enrichment", {}).get("mitre_techniques", []) or []),
                    "cves": ";".join(rec.get("enrichment", {}).get("cves", []) or []),
                    "tools": ";".join(rec.get("enrichment", {}).get("tools", []) or []),
                    "campaigns": ";".join(rec.get("enrichment", {}).get("campaigns", []) or [])
                }

                # Process IOCs and write rows to the CSV
                iocs = rec.get("iocs", {})
                if not iocs:
                    logging.warning(f"No IOCs found for record: {rec.get('title', 'No Title')}")
                    
                    continue

                for typ, vals in iocs.items():
                    if not isinstance(vals, list):
                        logging.warning(f"Skipping invalid IOC type '{typ}' for record: {rec.get('title', 'No Title')}")
                        continue

                    for val in vals:
                        row["attribute_type"] = typ.rstrip("s")
                        row["attribute_value"] = val
                        row["attribute_timestamp"] = rec.get("timestamp", "")
                        writer.writerow(row)

        # Log success message
        logging.info(f"✅ Successfully wrote {len(all_records)} records to {csv_path}")
        if log_file:
            with open(log_file, "a", encoding="utf-8") as log:
                log.write(f"✅ Successfully wrote {len(all_records)} records to {csv_path}\n")

    except Exception as e:
        error_message = f"Failed to write CSV feed to {csv_path}: {e}"
        logging.error(error_message)
        if log_file:
            with open(log_file, "a", encoding="utf-8") as log:
                log.write(error_message + "\n")