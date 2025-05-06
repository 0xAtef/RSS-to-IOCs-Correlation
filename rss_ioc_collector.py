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
from urllib.parse import urlparse, quote_plus
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

# Required config values
GITHUB_REPO    = cfg.get("github_repo")  # e.g. "0xAtef/RSS-to-IOCs-Correlation"
GITHUB_BRANCH  = cfg.get("github_branch", "main")
ORG_NAME       = cfg.get("org_name")
ORG_UUID       = cfg.get("org_uuid")
if not GITHUB_REPO or not ORG_NAME or not ORG_UUID:
    logging.error("config.json must include 'github_repo', 'org_name', and 'org_uuid'.")
    sys.exit(1)

FEED_URLS      = cfg.get("feed_urls", [])
MAX_DAYS_OLD   = cfg.get("max_days_old", 20)
OUTPUT_BASE_DIR= cfg.get("output_base_dir", "misp_feed")
SEEN_IOCS_PATH = cfg.get("seen_iocs_path", "seen_iocs.json")
MAX_WORKERS    = cfg.get("max_workers", 5)
IOC_PATTERNS   = cfg.get("ioc_patterns", {})
IOC_CONTEXT_KEYWORDS = cfg.get("ioc_context_keywords", {})
FEED_TAGS      = cfg.get("feed_tags_by_feed", {})
WHITELIST_BY_FEED= cfg.get("whitelist_by_feed", {})

# Paths
EVENTS_DIR     = os.path.join(OUTPUT_BASE_DIR, "events")
ROOT_MANIFEST  = os.path.join(OUTPUT_BASE_DIR, "manifest.json")

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
retry = Retry(total=cfg.get("http_retry_total",3),
              backoff_factor=cfg.get("http_backoff_factor",1),
              status_forcelist=cfg.get("http_status_forcelist",[429,500,502,503,504]))
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

# ── UTILITIES ─────────────────────────────────────────────────────────────────
def strip_html(html):
    return BeautifulSoup(html, "html.parser").get_text()

def parse_entry_date(e):
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

def recent(e):
    dt = parse_entry_date(e)
    return bool(dt and dt >= datetime.utcnow() - timedelta(days=MAX_DAYS_OLD))

def extract_iocs(text):
    return {t: list({m for m in re.findall(pat, text)}) for t, pat in IOC_PATTERNS.items()}

def context_tags(text, feed_url):
    tags = set(cfg.get("fixed_tags", []))
    lt = text.lower()
    for ctx, kws in IOC_CONTEXT_KEYWORDS.items():
        if any(k in lt for k in kws):
            tags.add(ctx)
    tags.update(FEED_TAGS.get(feed_url, []))
    return list(tags)

# ── PROCESSING ────────────────────────────────────────────────────────────────
def process_feed(feed_url, seen):
    logging.info(f"→ Fetching: {feed_url}")
    feed = feedparser.parse(feed_url)
    new_records = []
    for e in feed.entries:
        if not recent(e): continue
        link = e.get("link", "")
        try:
            resp = session.get(link, timeout=cfg.get("request_timeout",10), headers={"User-Agent": cfg.get("user_agent")})
            text = strip_html(resp.text)
        except Exception as exc:
            logging.error(f"Error GET {link}: {exc}")
            continue
        raw = extract_iocs(text)
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
        if not any(filtered.values()): continue
        new_records.append({
            "id": str(uuid.uuid4()),
            "title": e.get("title", ""),
            "source": link,
            "published": (parse_entry_date(e) or datetime.utcnow()).isoformat(),
            "feed": feed_url,
            "iocs": filtered,
            "tags": context_tags(text, feed_url),
            "context": enrich_with_ner(text)
        })
    logging.info(f"→ Found {len(new_records)} new IOCs in {feed_url}")
    return new_records

# ── WRITE EVENTS & MANIFEST ───────────────────────────────────────────────────
def write_event(uuid_str, rec):
    # Build MISP-compliant event JSON with attributes
    attributes = []
    for ioc_type, values in rec.get("iocs", {}).items():
        for val in values:
            attr = {
                "type": ioc_type,
                "category": "External analysis",
                "to_ids": True,
                "value": val,
                "comment": f"Extracted from: {rec.get('source', '')}",
                "timestamp": int(datetime.utcnow().timestamp()),
            }
            attributes.append(attr)

    event = {"Event": {
        "uuid": uuid_str,
        "info": rec["title"],
        "date": rec["published"].split('T')[0],
        "analysis": cfg.get("misp_analysis", 0),
        "threat_level_id": cfg.get("misp_threat_level_id", 4),
        "timestamp": int(datetime.utcnow().timestamp()),
        "Orgc": {"name": ORG_NAME, "uuid": ORG_UUID},
        "Tag": [{"name": t, "colour": cfg.get("misp_tag_colour", "#004646"), "local": False, "relationship_type": ""} for t in rec.get("tags", [])],
        "Attribute": attributes
    }}

    os.makedirs(EVENTS_DIR, exist_ok=True)
    path = os.path.join(EVENTS_DIR, f"{uuid_str}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(event, f, indent=2)




def rebuild_root_manifest():
    entries = []
    feed_root = OUTPUT_BASE_DIR.strip("/")
    for fn in glob(os.path.join(EVENTS_DIR, "*.json")):
        name = os.path.basename(fn)
        if name == "manifest.json":
            continue
        uid = name.rsplit(".", 1)[0]
        url = "/".join([
            "https://raw.githubusercontent.com",
            GITHUB_REPO,
            GITHUB_BRANCH,
            feed_root,
            "events",
            name
        ])
        entries.append({
            "uuid": uid,
            "url": url
        })

    root_manifest = {
        "name": cfg.get("feed_name", "RSS to IOC Collector Feed"),
        "description": cfg.get("feed_description", "IOC feed generated from RSS sources"),
        "version": 1,
        "publish_timestamp": int(datetime.utcnow().timestamp()),
        "url": f"https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_BRANCH}/{feed_root}",
        "events": entries
    }

    os.makedirs(OUTPUT_BASE_DIR, exist_ok=True)
    with open(ROOT_MANIFEST, "w", encoding="utf-8") as f:
        json.dump(root_manifest, f, indent=2)




# ── MAIN ──────────────────────────────────────────────────────────────────────
def main():
    logging.info("IOC Collector START")
    seen = load_seen_iocs()
    all_recs = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_feed, url, seen): url for url in FEED_URLS}
        for fut in as_completed(futures):
            all_recs.extend(fut.result())
    save_seen_iocs(seen)

    # Write events and rebuild manifest
    for rec in all_recs:
        write_event(rec['id'], rec)
    rebuild_root_manifest()
    logging.info(f"Wrote {len(all_recs)} events and rebuilt manifest at {ROOT_MANIFEST}")

if __name__ == "__main__":
    main()
