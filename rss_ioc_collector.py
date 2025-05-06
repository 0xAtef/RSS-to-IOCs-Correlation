#!/usr/bin/env python3
import json
import os
import sys
import logging
import requests
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.csv_writer import write_csv_feed
from utils.feed_health import monitor_feed_health
from utils.fetch_parse import process_feed

# === FOLDER STRUCTURE ===
CONFIG_DIR = "config"
LOGS_DIR = "logs"
OUTPUT_DIR = "output"
MISP_FEED_DIR = "misp_feed"  # Add MISP feed directory

# Ensure required directories exist
os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(MISP_FEED_DIR, exist_ok=True)  # Ensure MISP feed directory exists
os.makedirs(LOGS_DIR, exist_ok=True)

# Configure logging
LOG_FILE = os.path.join(LOGS_DIR, "ioc_collector.log")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, mode="a", encoding="utf-8")
    ]
)

# Add a test log to confirm logging is initialized
logging.info("Logging initialized. Starting script...")

# === FILE PATHS ===
CONFIG_PATH = os.path.join("config", "config.json")
LOG_FILE = os.path.join("logs", "ioc_collector.log")
SEEN_IOCS_PATH = os.path.join("output", "seen_iocs.json")
CSV_PATH = os.path.join("misp_feed", "feed.csv")
# === LOAD CONFIGURATION FROM FILE ===
with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    cfg = json.load(f)

# Required
ORG_NAME = cfg["org_name"]
ORG_UUID = cfg["org_uuid"]

FEED_URLS = cfg.get("feed_urls", [])
MAX_DAYS_OLD = cfg.get("max_days_old", 20)
MAX_WORKERS = cfg.get("max_workers", 5)

# ── Logging ────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, mode="a", encoding="utf-8")
    ]
)

# ── HTTP SESSION ─────────────────────────────────────────────────
session = requests.Session()
retry = Retry(total=cfg.get("http_retry_total", 3),
              backoff_factor=cfg.get("http_backoff_factor", 1),
              status_forcelist=cfg.get("http_status_forcelist", [429, 500, 502, 503, 504]))
session.mount("https://", HTTPAdapter(max_retries=retry))
session.mount("http://", HTTPAdapter(max_retries=retry))

# ── STATE ─────────────────────────────────────────────────────────
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
        # Initialize as an empty set
        with open(SEEN_IOCS_PATH, "w") as f:
            json.dump([], f)
        return set()


def save_seen(seen):
    """Save the set of seen IOCs to a file."""
    try:
        with open(SEEN_IOCS_PATH, "w") as f:
            json.dump(sorted(seen), f, indent=2)
        logging.info(f"Seen IOCs saved to {SEEN_IOCS_PATH}")
    except Exception as e:
        logging.error(f"Failed to save seen IOCs to {SEEN_IOCS_PATH}: {e}")


def validate_config(cfg):
    """Validate the configuration file for required keys."""
    required_keys = ["org_name", "org_uuid", "feed_urls", "output_base_dir", "seen_iocs_path"]
    for key in required_keys:
        if key not in cfg:
            logging.error(f"Missing required configuration key: {key}")
            sys.exit(1)


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
                cfg["ioc_patterns"],  # Pass ioc_patterns
                cfg.get("whitelist_by_feed", {}),  # Pass whitelist_by_feed
                cfg["max_days_old"]  # Pass max_days_old
            ): url
            for url in feed_urls if monitor_feed_health(url, session)  # Only process healthy feeds
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


# ── MAIN ────────────────────────────────────────────────────────────────
def main():
    validate_config(cfg)
    logging.info(f"Feed URLs to process: {FEED_URLS}")
    if not FEED_URLS:
        logging.error("No feed URLs provided in the configuration.")
        sys.exit(1)
    seen = load_seen()
    try:
        all_recs = process_feeds_concurrently(FEED_URLS, seen)
        save_seen(seen)
        write_csv_feed(all_recs, CSV_PATH, ORG_UUID, ORG_NAME, cfg)
    finally:
        cleanup()


if __name__ == "__main__":
    main()