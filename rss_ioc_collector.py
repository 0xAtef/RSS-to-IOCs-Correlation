#!/usr/bin/env python3
import json
import os
import sys
import logging
import requests
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from utils.csv_writer import write_csv_feed
from utils.feed_health import monitor_feed_health
from utils.fetch_parse import process_feed

# === FOLDER STRUCTURE ===
CONFIG_DIR = "config"
LOGS_DIR = "logs"
OUTPUT_DIR = "output"
MISP_FEED_DIR = "misp_feed"

# Ensure required directories exist
os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(MISP_FEED_DIR, exist_ok=True)

# === FILE PATHS ===
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
LOG_FILE = os.path.join(LOGS_DIR, "ioc_collector.log")
SEEN_IOCS_PATH = os.path.join(OUTPUT_DIR, "seen_iocs.json")
CSV_PATH = os.path.join(MISP_FEED_DIR, "feed.csv")

# === LOAD CONFIGURATION FROM FILE ===
with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    cfg = json.load(f)

# Configure logging
debug_mode = cfg.get("debug_mode", False)
logging.basicConfig(
    level=logging.DEBUG if debug_mode else logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, mode="a", encoding="utf-8")
    ]
)

logging.info("Logging initialized. Starting script...")

# Required configuration
ORG_NAME = cfg["org_name"]
ORG_UUID = cfg["org_uuid"]
FEED_URLS = cfg.get("feed_urls", [])
MAX_DAYS_OLD = cfg.get("max_days_old", 20)
MAX_WORKERS = cfg.get("max_workers", 5)

# HTTP session with retries
session = requests.Session()
retry = Retry(
    total=cfg.get("http_retry_total", 3),
    backoff_factor=cfg.get("http_backoff_factor", 1),
    status_forcelist=cfg.get("http_status_forcelist", [429, 500, 502, 503, 504]),
    raise_on_status=False
)
session.mount("https://", HTTPAdapter(max_retries=retry))
session.mount("http://", HTTPAdapter(max_retries=retry))
session.headers.update({"User-Agent": cfg.get("user_agent", "RSS-IOC-Collector")})

# Global state
global_seen = set()

def load_seen():
    """Load the set of seen IOCs from a file."""
    try:
        with open(SEEN_IOCS_PATH, "r") as f:
            return set(json.load(f))
    except FileNotFoundError:
        logging.warning(f"Seen IOCs file not found: {SEEN_IOCS_PATH}. Starting fresh.")
        return set()
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from {SEEN_IOCS_PATH}: {e}")
        with open(SEEN_IOCS_PATH, "w") as f:
            json.dump([], f)
        return set()

def save_seen(seen):
    """Save the set of seen IOCs to a file."""
    try:
        backup_path = SEEN_IOCS_PATH + ".bak"
        if os.path.exists(SEEN_IOCS_PATH):
            os.rename(SEEN_IOCS_PATH, backup_path)  # Create a backup
        with open(SEEN_IOCS_PATH, "w") as f:
            json.dump(sorted(seen), f, indent=2)
        logging.info(f"Seen IOCs saved to {SEEN_IOCS_PATH}")
    except Exception as e:
        logging.error(f"Failed to save seen IOCs to {SEEN_IOCS_PATH}: {e}")

def validate_config(cfg):
    """Validate the configuration file for required keys and values."""
    required_keys = ["org_name", "org_uuid", "feed_urls", "output_base_dir", "seen_iocs_path"]
    for key in required_keys:
        if key not in cfg:
            logging.error(f"Missing required configuration key: {key}")
            sys.exit(1)
    if not isinstance(cfg.get("feed_urls", []), list) or not cfg["feed_urls"]:
        logging.error("The 'feed_urls' key must be a non-empty list.")
        sys.exit(1)
    if not isinstance(cfg.get("org_uuid", ""), str) or len(cfg["org_uuid"]) != 36:
        logging.error("The 'org_uuid' key must be a valid UUID.")
        sys.exit(1)

    # Set defaults for optional keys
    cfg.setdefault("max_days_old", 20)
    cfg.setdefault("max_workers", 5)
    cfg.setdefault("ioc_patterns", {})
    cfg.setdefault("whitelist_by_feed", {})

def cleanup():
    """Perform cleanup tasks, such as resetting global variables."""
    global global_seen
    global_seen.clear()
    logging.info("Cleanup completed.")

def process_feeds_concurrently(feed_urls, seen):
    """Process multiple feeds concurrently."""
    logging.info(f"Starting to process {len(feed_urls)} feeds.")
    all_recs = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(
                process_feed,
                url,
                seen,
                global_seen,
                session,
                cfg,
                cfg["ioc_patterns"],
                cfg.get("whitelist_by_feed", {}),
                cfg["max_days_old"]
            ): url
            for url in feed_urls if monitor_feed_health(url, session)
        }
        for future in as_completed(futures):
            feed_url = futures[future]
            try:
                result = future.result()
                if result:
                    logging.info(f"Processed feed: {feed_url}, Records found: {len(result)}")
                else:
                    logging.warning(f"No records found in feed: {feed_url}")
                all_recs.extend(result)
            except Exception as exc:
                logging.error(f"Error processing feed {feed_url}: {exc}")
    logging.info(f"Finished processing feeds. Total records collected: {len(all_recs)}")
    return all_recs

def main():
    start_time = datetime.utcnow()
    validate_config(cfg)
    logging.info(f"Feed URLs to process: {FEED_URLS}")
    if not FEED_URLS:
        logging.error("No feed URLs provided in the configuration.")
        sys.exit(1)
    seen = load_seen()
    try:
        all_recs = process_feeds_concurrently(FEED_URLS, seen)
        valid_recs = [rec for rec in all_recs if "title" in rec and "source" in rec]
        if len(valid_recs) < len(all_recs):
            logging.warning(f"Some entries are missing required fields and will be skipped.")
        save_seen(seen)
        write_csv_feed(valid_recs, CSV_PATH, ORG_UUID, ORG_NAME, cfg)

        # Save output.json
        output_data = {"records": valid_recs}
        try:
            with open("output/output.json", "w") as f:
                json.dump(output_data, f, indent=2)
            logging.info("output.json saved successfully.")
        except Exception as e:
            logging.error(f"Failed to save output.json: {e}")

        logging.info("=== Summary ===")
        logging.info(f"Total feeds processed: {len(FEED_URLS)}")
        logging.info(f"Total records collected: {len(all_recs)}")
        logging.info(f"Total valid records saved: {len(valid_recs)}")
        logging.info(f"Total seen IOCs saved: {len(seen)}")
        end_time = datetime.utcnow()
        logging.info(f"Total runtime: {end_time - start_time}")

    finally:
        cleanup()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)