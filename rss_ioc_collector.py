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

# Ensure required directories exist
os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# === FILE PATHS ===
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
LOG_FILE = os.path.join(LOGS_DIR, "ioc_collector.log")
SEEN_IOCS_PATH = os.path.join(OUTPUT_DIR, "seen_iocs.json")
CSV_PATH = os.path.join(OUTPUT_DIR, "feed.csv")

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
        return set()
    except Exception as e:
        logging.error(f"Unexpected error loading seen IOCs: {e}")
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
            executor.submit(process_feed, url, seen, global_seen, session, cfg): url
            for url in feed_urls if monitor_feed_health(url, session)  # Only process healthy feeds
        }
        for future in as_completed(futures):
            try:
                all_recs.extend(future.result())
            except Exception as exc:
                logging.error(f"Error processing feed {futures[future]}: {exc}")
    logging.info(f"Finished processing feeds. Total records collected: {len(all_recs)}")
    return all_recs


# ── MAIN ────────────────────────────────────────────────────────────────
def main():
    validate_config(cfg)
    seen = load_seen()
    try:
        all_recs = process_feeds_concurrently(FEED_URLS, seen)
        save_seen(seen)
        write_csv_feed(all_recs, CSV_PATH, ORG_UUID, ORG_NAME, cfg)
    finally:
        cleanup()


if __name__ == "__main__":
    main()