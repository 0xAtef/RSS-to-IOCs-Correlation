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
                # Translate event info to English if necessary
                info = translate_to_english(rec["title"])

                evt_uuid = rec["id"]
                date = rec["published"].split("T")[0]
                analysis = cfg.get("misp_analysis", 0)
                tlid = cfg.get("misp_threat_level_id", 4)
                comment = translate_to_english(f"Extracted from: {rec['source']}")

                tags = rec.get("tags", [])
                tags_str = ";".join(tags) if tags else ""

                enrichment = rec.get("enrichment", {})
                actors = ";".join(enrichment.get("actors", []))
                malware = ";".join(enrichment.get("malware", []))
                techniques = ";".join(enrichment.get("mitre_techniques", []))
                cves = ";".join(enrichment.get("cves", []))
                tools = ";".join(enrichment.get("tools", []))
                campaigns = ";".join(enrichment.get("campaigns", []))

                for typ, vals in rec["iocs"].items():
                    for val in vals:
                        attribute_timestamp = rec.get("timestamp", "")

                        w.writerow({
                            "uuid": evt_uuid,
                            "info": info,
                            "date": date,
                            "threat_level_id": tlid,
                            "analysis": analysis,
                            "orgc_uuid": org_uuid,
                            "orgc_name": org_name,
                            "tag": tags_str,
                            "attribute_category": "External analysis",
                            "attribute_type": typ.rstrip("s"),
                            "attribute_value": val,
                            "to_ids": "True",
                            "comment": comment,
                            "attribute_timestamp": attribute_timestamp,
                            "actors": actors,
                            "malware": malware,
                            "mitre_techniques": techniques,
                            "cves": cves,
                            "tools": tools,
                            "campaigns": campaigns
                        })

        logging.info(f"✅ Wrote MISP-compatible CSV feed to {csv_path}")
    except Exception as e:
        logging.error(f"Failed to write CSV feed: {e}")