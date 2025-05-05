import feedparser
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import re
import json
import logging
import uuid
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.normalization import normalize_ioc, is_ioc_whitelisted
from utils.enrichment import enrich_with_ner

# === LOAD CONFIGURATION FROM FILE ===
with open("config.json", "r", encoding="utf-8") as cfg_file:
    cfg = json.load(cfg_file)

FEED_URLS = cfg.get("feed_urls", [])
MAX_DAYS_OLD = cfg.get("max_days_old", 20)
OUTPUT_JSON_PATH = cfg.get("output_json_path", "output.json")
SEEN_IOCS_PATH = cfg.get("seen_iocs_path", "seen_iocs.json")
WHITELIST_BY_FEED = cfg.get("whitelist_by_feed", {})
IOC_CONTEXT_KEYWORDS = cfg.get("ioc_context_keywords", {})
IOC_PATTERNS = cfg.get("ioc_patterns", {})
MAX_WORKERS = cfg.get("max_workers", 5)
FEED_TAGS = cfg.get("feed_tags", {})

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(cfg.get("log_file", "ioc_collector.log")),
        logging.StreamHandler()
    ]
)

# Initialize HTTP session with retry logic
http_session = requests.Session()
http_retries = Retry(
    total=cfg.get("http_retry_total", 3),
    backoff_factor=cfg.get("http_backoff_factor", 1),
    status_forcelist=cfg.get("http_status_forcelist", [429, 500, 502, 503, 504])
)
http_session.mount("https://", HTTPAdapter(max_retries=http_retries))
http_session.mount("http://", HTTPAdapter(max_retries=http_retries))

def load_seen_iocs_set():
    try:
        with open(SEEN_IOCS_PATH, "r", encoding="utf-8") as f:
            return set(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError):
        return set()

def persist_seen_iocs(ioc_set):
    with open(SEEN_IOCS_PATH, "w", encoding="utf-8") as f:
        json.dump(sorted(list(ioc_set)), f, indent=2)

def strip_html_tags(html_content):
    return BeautifulSoup(html_content, "html.parser").get_text()

def parse_entry_date(entry):
    struct = entry.get("published_parsed") or entry.get("updated_parsed")
    if struct:
        return datetime(*struct[:6])
    for key in ("published", "updated", "pubDate"):
        raw_date = entry.get(key)
        if raw_date:
            parsed = feedparser._parse_date(raw_date)
            if parsed:
                return datetime(*parsed[:6])
    return None

def is_entry_recent(entry):
    entry_dt = parse_entry_date(entry)
    return bool(entry_dt and entry_dt >= (datetime.utcnow() - timedelta(days=MAX_DAYS_OLD)))

def extract_iocs_from_text(text_content):
    return {ioc_type: list(set(re.findall(pattern, text_content)))
            for ioc_type, pattern in IOC_PATTERNS.items()}

def extract_context_tags(text_content, feed_url):
    tags = set(["RSS to IOC Collector"])
    lower_text = text_content.lower()
    for context, keywords in IOC_CONTEXT_KEYWORDS.items():
        if any(kw in lower_text for kw in keywords):
            tags.add(context)
    tags.update(FEED_TAGS.get(feed_url, []))
    return list(tags)

def process_feed_url(feed_url, seen_iocs):
    feed_domain = urlparse(feed_url).netloc.lower()
    logging.info(f"-> Processing feed: {feed_url}")
    results = []
    feed = feedparser.parse(feed_url)
    for entry in feed.entries:
        if not is_entry_recent(entry):
            continue
        title = entry.get("title", "<no title>")
        link = entry.get("link", "")
        published_dt = parse_entry_date(entry)
        try:
            response = http_session.get(
                link,
                headers={"User-Agent": cfg.get("user_agent", "MISP-IOC-Collector/1.0")},
                timeout=cfg.get("request_timeout", 10)
            )
            text = strip_html_tags(response.text)
            raw_iocs = extract_iocs_from_text(text)
            for fname in raw_iocs.get("filenames", []):
                raw_iocs["domains"] = [d for d in raw_iocs.get("domains", []) if fname.lower() not in d.lower()]
                raw_iocs["urls"] = [u for u in raw_iocs.get("urls", []) if fname.lower() not in u.lower()]
            filtered_iocs = {}
            for ioc_type, ioc_list in raw_iocs.items():
                new_iocs = []
                for ioc in ioc_list:
                    norm = normalize_ioc(ioc)
                    if norm in seen_iocs or is_ioc_whitelisted(ioc, feed_domain, WHITELIST_BY_FEED):
                        continue
                    new_iocs.append(ioc)
                    seen_iocs.add(norm)
                filtered_iocs[ioc_type] = new_iocs
            if any(filtered_iocs.values()):
                record = {
                    "id": str(uuid.uuid4()),
                    "title": title,
                    "source": link,
                    "published": published_dt.isoformat() if published_dt else "",
                    "feed": feed_url,
                    "iocs": filtered_iocs,
                    "tags": extract_context_tags(text, feed_url),
                    "context": enrich_with_ner(text)
                }
                results.append(record)
        except Exception as error:
            logging.error(f"Error fetching {link}: {error}")
    logging.info(f"-> {len(results)} new records from {feed_url}")
    return results

def run_ioc_collector():
    logging.info("IOC Collector started.")
    seen_iocs = load_seen_iocs_set()
    all_ioc_records = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_feed_url, url.strip(), seen_iocs): url for url in FEED_URLS}
        for future in as_completed(futures):
            try:
                all_ioc_records.extend(future.result())
            except Exception as exc:
                logging.error(f"Error processing feed: {exc}")
    with open(OUTPUT_JSON_PATH, "w", encoding="utf-8") as outfile:
        json.dump(all_ioc_records, outfile, indent=2, ensure_ascii=False)
    persist_seen_iocs(seen_iocs)
    logging.info(f"Wrote {len(all_ioc_records)} total records to {OUTPUT_JSON_PATH}")
    logging.info("IOC Collector finished.")

if __name__ == "__main__":
    run_ioc_collector()
    with open(OUTPUT_JSON_PATH, "r", encoding="utf-8") as f:
        records = json.load(f)
