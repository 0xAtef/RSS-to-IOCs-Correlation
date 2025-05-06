#!/usr/bin/env python3
import csv
import json
import os
import sys
import uuid
import logging
import feedparser
import requests
import re

from urllib.parse import urlparse
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.normalization import normalize_ioc, is_ioc_whitelisted
from utils.enrichment    import enrich_with_ner

# === LOAD CONFIGURATION FROM FILE ===
with open("config.json", "r", encoding="utf-8") as f:
    cfg = json.load(f)

# Required
ORG_NAME    = cfg["org_name"]
ORG_UUID    = cfg["org_uuid"]

FEED_URLS         = cfg.get("feed_urls", [])
MAX_DAYS_OLD      = cfg.get("max_days_old", 20)
OUTPUT_BASE_DIR   = cfg.get("output_base_dir", "misp_feed")
CSV_PATH          = os.path.join(OUTPUT_BASE_DIR, "feed.csv")
SEEN_IOCS_PATH    = cfg.get("seen_iocs_path", "seen_iocs.json")
MAX_WORKERS       = cfg.get("max_workers", 5)
IOC_PATTERNS      = cfg.get("ioc_patterns", {})
IOC_CONTEXT_KW    = cfg.get("ioc_context_keywords", {})
FEED_TAGS         = cfg.get("feed_tags_by_feed", {})
WHITELIST_BY_FEED = cfg.get("whitelist_by_feed", {})

# Ensure output dir
os.makedirs(OUTPUT_BASE_DIR, exist_ok=True)

# ── Logging ────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

# ── HTTP SESSION ─────────────────────────────────────────────────
session = requests.Session()
retry = Retry(total=cfg.get("http_retry_total", 3),
              backoff_factor=cfg.get("http_backoff_factor", 1),
              status_forcelist=cfg.get("http_status_forcelist", [429,500,502,503,504]))
session.mount("https://", HTTPAdapter(max_retries=retry))
session.mount("http://", HTTPAdapter(max_retries=retry))

# ── STATE ─────────────────────────────────────────────────────────
def load_seen():
    try:
        with open(SEEN_IOCS_PATH, "r") as f:
            return set(json.load(f))
    except:
        return set()

def save_seen(seen):
    with open(SEEN_IOCS_PATH, "w") as f:
        json.dump(sorted(seen), f, indent=2)

# ── UTILITIES ─────────────────────────────────────────────────────
def strip_html(html):
    return BeautifulSoup(html, "html.parser").get_text()

def parse_date(e):
    sd = e.get("published_parsed") or e.get("updated_parsed")
    if sd:
        return datetime(*sd[:6])
    return None

def recent(e):
    d = parse_date(e)
    return bool(d and d >= datetime.utcnow() - timedelta(days=MAX_DAYS_OLD))

def extract_iocs(text):
    clean = text.replace("\n"," ")
    return {t: list({m for m in re.findall(pat, clean)}) for t, pat in IOC_PATTERNS.items()}

def context_tags(text, feed_url):
    tags = set(cfg.get("fixed_tags", []))
    lt = text.lower()
    for ctx, kws in IOC_CONTEXT_KW.items():
        if any(k in lt for k in kws):
            tags.add(ctx)
    tags.update(FEED_TAGS.get(feed_url, []))
    return list(tags)

# ── FETCH & PARSE ────────────────────────────────────────────────────
def fetch_feed(feed_url):
    """Fetch the RSS feed and return the parsed content."""
    try:
        logging.info(f"Fetching {feed_url}")
        response = session.get(feed_url, timeout=cfg.get("request_timeout", 10),
                               headers={"User-Agent": cfg.get("user_agent")})
        response.raise_for_status()
        return feedparser.parse(response.text)
    except requests.exceptions.RequestException as exc:
        logging.error(f"Error fetching {feed_url}: {exc}")
        return None

def process_feed(feed_url, seen):
    """Process a single feed URL and extract IOCs."""
    feed = fetch_feed(feed_url)
    if not feed or not feed.entries:
        logging.warning(f"No entries found in {feed_url}")
        return []

    out = []
    for e in feed.entries:
        if not recent(e):
            continue

        link = e.get("link", "")
        try:
            r = session.get(link, timeout=cfg.get("request_timeout", 10),
                            headers={"User-Agent": cfg.get("user_agent")})
            r.raise_for_status()
            text = strip_html(r.text)
        except requests.exceptions.RequestException as exc:
            logging.error(f"Error fetching article {link}: {exc}")
            continue

        raw = extract_iocs(text)
        filtered = {}
        for typ, vals in raw.items():
            keep = []
            for v in vals:
                n = normalize_ioc(v)
                if n in seen or is_ioc_whitelisted(v, urlparse(feed_url).netloc, WHITELIST_BY_FEED):
                    continue
                seen.add(n)
                keep.append(v)
            filtered[typ] = keep

        if not any(filtered.values()):
            continue

        out.append({
            "id":        str(uuid.uuid4()),
            "title":     e.get("title", ""),
            "source":    link,
            "published": (parse_date(e) or datetime.utcnow()).isoformat(),
            "feed":      feed_url,
            "iocs":      filtered,
            "tags":      context_tags(text, feed_url)
        })

    logging.info(f"Found {len(out)} new entries in {feed_url}")
    return out

def process_feeds_concurrently(feed_urls, seen):
    """Process multiple feeds concurrently."""
    all_recs = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_feed, url, seen): url for url in feed_urls}
        for future in as_completed(futures):
            try:
                all_recs.extend(future.result())
            except Exception as exc:
                logging.error(f"Error processing feed {futures[future]}: {exc}")
    return all_recs

# ── WRITE CSV ────────────────────────────────────────────────────────
def write_csv_feed(all_records):
    fieldnames = [
        "uuid", "info", "date", "threat_level_id", "analysis",
        "orgc_uuid", "orgc_name", "tag", "attribute_category", "attribute_type",
        "attribute_value", "to_ids", "comment", "attribute_timestamp"
    ]

    with open(CSV_PATH, "w", newline="", encoding="utf-8") as csvf:
        w = csv.DictWriter(csvf, fieldnames=fieldnames)
        w.writeheader()

        for rec in all_records:
            evt_uuid  = rec["id"]
            info      = rec["title"]
            date      = rec["published"].split("T")[0]
            analysis  = cfg.get("misp_analysis", 0)
            tlid      = cfg.get("misp_threat_level_id", 4)
            comment   = f"Extracted from: {rec['source']}"
            
            # Assuming tags can be added (either from data or hardcoded)
            tags = rec.get("tags", [])
            tags_str = ";".join(tags) if tags else ""

            for typ, vals in rec["iocs"].items():
                for val in vals:
                    # Get timestamp for the attribute, if available
                    attribute_timestamp = rec.get("timestamp", "")

                    w.writerow({
                        "uuid":              evt_uuid,
                        "info":              info,
                        "date":              date,
                        "threat_level_id":   tlid,
                        "analysis":          analysis,
                        "orgc_uuid":         ORG_UUID,
                        "orgc_name":         ORG_NAME,
                        "tag":               tags_str,  # Add tags if present
                        "attribute_category":"External analysis",
                        "attribute_type":    typ.rstrip("s"),  # Ensure it's a valid type
                        "attribute_value":   val,
                        "to_ids":            "True",
                        "comment":           comment,
                        "attribute_timestamp": attribute_timestamp  # Add timestamp if available
                    })

    logging.info(f"✅ Wrote MISP-compatible CSV feed to {CSV_PATH}")

# ── MAIN ────────────────────────────────────────────────────────────────
def main():
    seen = load_seen()
    all_recs = process_feeds_concurrently(FEED_URLS, seen)
    save_seen(seen)
    write_csv_feed(all_recs)

if __name__ == "__main__":
    main()
