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
def process_feed(feed_url, seen):
    logging.info(f"Fetching {feed_url}")
    feed = feedparser.parse(feed_url)
    out = []
    for e in feed.entries:
        if not recent(e): continue
        link = e.get("link","")
        try:
            r = session.get(link, timeout=cfg.get("request_timeout",10),
                            headers={"User-Agent": cfg.get("user_agent")})
            text = strip_html(r.text)
        except Exception as exc:
            logging.error(f"  error GET {link}: {exc}")
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
            "title":     e.get("title",""),
            "source":    link,
            "published": (parse_date(e) or datetime.utcnow()).isoformat(),
            "feed":      feed_url,
            "iocs":      filtered,
            "tags":      context_tags(text, feed_url)
        })
    logging.info(f"Found {len(out)} new in {feed_url}")
    return out

# ── WRITE CSV ────────────────────────────────────────────────────────
def write_csv_feed(all_records):
    fieldnames = [
        "event_uuid","info","date","analysis","threat_level_id",
        "orgc_name","orgc_uuid","tag",
        "attribute_type","category","to_ids","value","comment","attribute_timestamp"
    ]
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as csvf:
        w = csv.DictWriter(csvf, fieldnames=fieldnames)
        w.writeheader()

        for rec in all_records:
            evt_id = rec["id"]
            info   = rec["title"]
            date   = rec["published"].split("T")[0]
            analysis = cfg.get("misp_analysis", 0)
            tlid     = cfg.get("misp_threat_level_id", 4)
            comment = f"Extracted from: {rec['source']}"
            ts      = int(datetime.utcnow().timestamp())

            # Set tag column once (not as separate attribute)
            tags_str = ",".join(rec["tags"])

            for typ, vals in rec["iocs"].items():
                for v in vals:
                    w.writerow({
                        "event_uuid":        evt_id,
                        "info":              info,
                        "date":              date,
                        "analysis":          analysis,
                        "threat_level_id":   tlid,
                        "orgc_name":         ORG_NAME,
                        "orgc_uuid":         ORG_UUID,
                        "tag":               tags_str,  # ⬅️ just metadata
                        "attribute_type":    typ.rstrip("s"),
                        "category":          "External analysis",
                        "to_ids":            True,
                        "value":             v,
                        "comment":           comment,
                        "attribute_timestamp": ts
                    })

    logging.info(f"Wrote CSV feed to {CSV_PATH}")


# ── MAIN ────────────────────────────────────────────────────────────────
def main():
    seen = load_seen()
    all_recs = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(process_feed, url, seen): url for url in FEED_URLS}
        for f in as_completed(futures):
            all_recs.extend(f.result())

    save_seen(seen)
    write_csv_feed(all_recs)

if __name__ == "__main__":
    main()
