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
from utils.ioc_utils import IOCUtils  # Consolidated IOC logic

# === FOLDER STRUCTURE ===
CONFIG_DIR = "config"
LOGS_DIR = "logs"
OUTPUT_DIR = "output"
MISP_FEED_DIR = "misp_feed"

# Ensure required directories exist
for directory in [CONFIG_DIR, LOGS_DIR, OUTPUT_DIR, MISP_FEED_DIR]:
    os.makedirs(directory, exist_ok=True)

# === FILE PATHS ===
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
LOG_FILE = os.path.join(LOGS_DIR, "ioc_collector.log")
SEEN_IOCS_PATH = os.path.join(OUTPUT_DIR, "seen_iocs.json")
CSV_PATH = os.path.join(MISP_FEED_DIR, "feed.csv")

# === LOAD CONFIGURATION ===
try:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
except FileNotFoundError:
    logging.critical(f"Configuration file not found at {CONFIG_PATH}. Exiting.")
    sys.exit(1)

# === CONFIGURE LOGGING ===
logging.basicConfig(
    level=logging.DEBUG if cfg.get("debug_mode", False) else logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, mode="a", encoding="utf-8")
    ]
)

logging.info("Logging initialized. Starting script...")

# === REQUIRED CONFIGURATION ===
ORG_NAME = cfg.get("org_name")
ORG_UUID = cfg.get("org_uuid")
FEED_URLS = cfg.get("feed_urls", [])
MAX_DAYS_OLD = cfg.get("max_days_old", 20)
MAX_WORKERS = cfg.get("max_workers", 5)
IOC_PATTERNS = cfg.get("ioc_patterns", {})
WHITELIST_BY_FEED = cfg.get("whitelist_by_feed", {})

# Validate configuration
if not ORG_NAME or not ORG_UUID or not FEED_URLS:
    logging.critical("Missing required configuration keys (org_name, org_uuid, feed_urls). Exiting.")
    sys.exit(1)

# === HTTP SESSION WITH RETRIES ===
def setup_http_session(cfg):
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
    logging.debug("HTTP session configured with retries.")
    return session

session = setup_http_session(cfg)

# Global state
global_seen = set()
ioc_utils = IOCUtils(whitelist_by_feed=WHITELIST_BY_FEED)

# === HELPER FUNCTIONS ===
def load_seen():
    """Load the set of seen IOCs from a file."""
    try:
        with open(SEEN_IOCS_PATH, "r") as f:
            return set(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError):
        logging.warning(f"Seen IOCs file not found or corrupted: {SEEN_IOCS_PATH}. Starting fresh.")
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
        logging.error(f"Failed to save seen IOCs: {e}")

def process_feeds_concurrently(feed_urls, seen):
    """Process multiple feeds concurrently."""
    logging.info(f"Starting to process {len(feed_urls)} feeds.")
    all_recs = []
    skipped_feeds = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(
                process_feed,
                url,
                seen,
                global_seen,
                session,
                cfg,
                IOC_PATTERNS,
                WHITELIST_BY_FEED,
                MAX_DAYS_OLD
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
                skipped_feeds.append(feed_url)
    logging.info(f"Finished processing feeds. Total records collected: {len(all_recs)}")
    return all_recs, skipped_feeds

def process_and_save_feeds(feed_urls, seen):
    all_recs, skipped_feeds = process_feeds_concurrently(feed_urls, seen)
    valid_recs = [rec for rec in all_recs if "title" in rec and "source" in rec]
    save_seen(seen)
    write_csv_feed(valid_recs, CSV_PATH, ORG_UUID, ORG_NAME, cfg)
    save_output_json(valid_recs)
    return valid_recs, skipped_feeds, all_recs

def save_output_json(records):
    output_data = {"records": records}
    with open("output/output.json", "w") as f:
        json.dump(output_data, f, indent=2)
    logging.info("output.json saved successfully.")

# === MAIN FUNCTION ===
def main():
    start_time = datetime.utcnow()
    seen = load_seen()
    try:
        valid_recs, skipped_feeds, all_recs = process_and_save_feeds(FEED_URLS, seen)

        # Summary
        end_time = datetime.utcnow()
        total_runtime = end_time - start_time
        avg_runtime_per_feed = total_runtime / len(FEED_URLS) if FEED_URLS else 0

        logging.info("=== Summary ===")
        logging.info(f"Total feeds processed: {len(FEED_URLS)}")
        logging.info(f"Total feeds skipped: {len(skipped_feeds)}")
        logging.info(f"Total records collected: {len(all_recs)}")
        logging.info(f"Total valid records saved: {len(valid_recs)}")
        logging.info(f"Total seen IOCs saved: {len(seen)}")
        logging.info(f"Total runtime: {total_runtime}")
        logging.info(f"Average runtime per feed: {avg_runtime_per_feed}")
    finally:
        global_seen.clear()
        logging.info("Cleanup completed.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)