#!/usr/bin/env python3
import json
import os
import sys
import uuid
import logging
import feedparser
import requests
import re

from glob import glob
from urllib.parse import urlparse
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.normalization import normalize_ioc, is_ioc_whitelisted
from utils.enrichment import enrich_with_ner

# === LOAD CONFIGURATION FROM FILE ===
with open("config.json", "r", encoding="utf-8") as cfg_file:
    cfg = json.load(cfg_file)

FEED_URLS        = cfg.get("feed_urls", [])
MAX_DAYS_OLD     = cfg.get("max_days_old", 20)
OUTPUT_BASE_DIR  = cfg.get("output_base_dir", ".")       # e.g. "./misp_feed"
SEEN_IOCS_PATH   = cfg.get("seen_iocs_path", "seen_iocs.json")
MAX_WORKERS      = cfg.get("max_workers", 5)
IOC_PATTERNS     = cfg.get("ioc_patterns", {})
IOC_CONTEXT_KEYWORDS = cfg.get("ioc_context_keywords", {})
FEED_TAGS        = cfg.get("feed_tags", {})
WHITELIST_BY_FEED= cfg.get("whitelist_by_feed", {})

EVENTS_DIR = os.path.join(OUTPUT_BASE_DIR, "events")
MANIFEST_PATH = os.path.join(EVENTS_DIR, "manifest.json")

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(cfg.get("log_file", "ioc_collector.log")),
        logging.StreamHandler(sys.stdout)
    ]
)

# ── HTTP SESSION ───────────────────────────────────────────────────────────────
session = requests.Session()
retry  = Retry(
    total      = cfg.get("http_retry_total", 3),
    backoff_factor = cfg.get("http_backoff_factor", 1),
    status_forcelist = cfg.get("http_status_forcelist", [429,500,502,503,504])
)
session.mount("https://", HTTPAdapter(max_retries=retry))
session.mount("http://", HTTPAdapter(max_retries=retry))

# ── STATE MANAGEMENT ───────────────────────────────────────────────────────────
def load_seen_iocs():
    try:
        with open(SEEN_IOCS_PATH, "r", encoding="utf-8") as f:
            return set(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError):
        return set()

def save_seen_iocs(seen):
    with open(SEEN_IOCS_PATH, "w", encoding="utf-8") as f:
        json.dump(sorted(seen), f, indent=2)

def load_manifest() -> dict:
    if os.path.exists(MANIFEST_PATH):
        with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_manifest(manifest: dict):
    os.makedirs(EVENTS_DIR, exist_ok=True)
    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

# ── UTILITIES ─────────────────────────────────────────────────────────────────
def strip_html(html: str) -> str:
    return BeautifulSoup(html, "html.parser").get_text()

def parse_entry_date(e) -> datetime:
    struct = e.get("published_parsed") or e.get("updated_parsed")
    if struct:
        return datetime(*struct[:6])
    for key in ("published","updated","pubDate"):
        raw = e.get(key)
        if raw:
            parsed = feedparser._parse_date(raw)
            if parsed:
                return datetime(*parsed[:6])
    return None

def recent(e) -> bool:
    dt = parse_entry_date(e)
    return bool(dt and dt >= datetime.utcnow() - timedelta(days=MAX_DAYS_OLD))

def extract_iocs(text: str) -> dict:
    found = {}
    for t, pat in IOC_PATTERNS.items():
        found[t] = list({m for m in re.findall(pat, text)})
    return found

def context_tags(text: str, feed_url: str) -> list:
    tags = {"RSS to IOC Collector"}
    lt = text.lower()
    for ctx, kws in IOC_CONTEXT_KEYWORDS.items():
        if any(k in lt for k in kws):
            tags.add(ctx)
    tags.update(FEED_TAGS.get(feed_url, []))
    return list(tags)

# ── PROCESSING ────────────────────────────────────────────────────────────────
def process_feed(feed_url: str, seen: set) -> list:
    logging.info(f"→ Fetching: {feed_url}")
    feed = feedparser.parse(feed_url)
    new_records = []
    for entry in feed.entries:
        if not recent(entry):
            continue

        link = entry.get("link","")
        try:
            resp = session.get(link, timeout=cfg.get("request_timeout",10),
                               headers={"User-Agent": cfg.get("user_agent")})
            text = strip_html(resp.text)
        except Exception as e:
            logging.error(f"Error GET {link}: {e}")
            continue

        raw = extract_iocs(text)
        # filter out whitelisted / seen
        filtered = {}
        for typ, lst in raw.items():
            keep = []
            for i in lst:
                norm = normalize_ioc(i)
                if norm in seen or is_ioc_whitelisted(i, urlparse(feed_url).netloc, WHITELIST_BY_FEED):
                    continue
                seen.add(norm)
                keep.append(i)
            filtered[typ] = keep

        if not any(filtered.values()):
            continue

        rec = {
            "id":        str(uuid.uuid4()),
            "title":     entry.get("title",""),
            "source":    link,
            "published": (parse_entry_date(entry) or datetime.utcnow()).isoformat(),
            "feed":      feed_url,
            "iocs":      filtered,
            "tags":      context_tags(text, feed_url),
            "context":   enrich_with_ner(text)
        }
        new_records.append(rec)

    logging.info(f"→ Found {len(new_records)} new IOCs in {feed_url}")
    return new_records

# ── WRITE OUT ──────────────────────────────────────────────────────────────────
def write_event(uuid_str: str, data: dict):
    # 1) individual file
    os.makedirs(EVENTS_DIR, exist_ok=True)
    path = os.path.join(EVENTS_DIR, f"{uuid_str}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    # 2) update flat manifest
    manifest = load_manifest()
    manifest[uuid_str] = data
    save_manifest(manifest)

def main():
    logging.info("IOC Collector START")
    seen = load_seen_iocs()
    all_recs = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exec:
        futures = {exec.submit(process_feed, url, seen): url for url in FEED_URLS}
        for fut in as_completed(futures):
            all_recs.extend(fut.result())

    save_seen_iocs(seen)
    logging.info(f"Persisted {len(seen)} seen IOCs")

    # write each to events/
    for rec in all_recs:
        write_event(rec["id"], rec)

    logging.info(f"Wrote {len(all_recs)} new events into {EVENTS_DIR}")
    logging.info("IOC Collector DONE")

if __name__ == "__main__":
    main()
