import feedparser
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
import re
import json
import logging
from datetime import datetime, timedelta

# === CONFIG ===
RSS_FEEDS = [
    "https://www.us-cert.gov/ncas/alerts.xml",
    "https://www.cert.ssi.gouv.fr/feed/",
    "http://feeds.feedburner.com/TheHackersNews",
    "https://krebsonsecurity.com/feed/",
    "https://www.bleepingcomputer.com/feed/",
    "https://www.cisa.gov/news.xml",
    "https://www.darkreading.com/rss.xml",
    "http://isc.sans.edu/rssfeed.xml",
    "https://newsroom.trendmicro.com/media-coverage?pagetemplate=rss",
    "https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v"
]

# How many days back to treat as “recent”
DAYS_BACK = 20

# Output files
OUTPUT_FILE     = "output.json"
SEEN_IOCS_FILE  = "seen_iocs.json"

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler("ioc_collector.log"),
        logging.StreamHandler()
    ]
)

# IOC keyword categories
IOC_KEYWORDS = {
    "c2":       ["command and control", "c2 server", "beacon", "callback", "control channel", "cnc", "command channel"],
    "payload":  ["payload", "dropper", "executable", "binary", "installer", "installer payload", "stub"],
    "malware":  ["malware", "ransomware", "trojan", "worm", "backdoor", "spyware", "adware", "rootkit"],
    "phishing": ["phishing", "spearphishing", "credential theft", "spoofing", "malicious link", "fake login"],
    "exploit":  ["exploit", "vulnerability", "zeroday", "buffer overflow", "heap spray", "remote code execution", "CVE-"],
    "ddos":     ["denial of service", "dos attack", "ddos", "flood", "amplification", "botnet"],
    "botnet":   ["botnet", "zombie", "drone", "bot herder", "command hub"],
    "crypto":   ["cryptomining", "coinminer", "mining malware", "cryptojacker", "coinhive"],
    "credential":["password", "credentials", "login", "auth token", "two-factor", "2fa", "otp", "session cookie"],
    "injection":["sql injection", "xss", "cross-site scripting", "code injection", "command injection"],
    "fraud":    ["fraud", "scam", "social engineering", "business email compromise", "impersonation"]
}

# IOC extraction regexes
patterns = {
    "ips":     r"(?:\d{1,3}\.){3}\d{1,3}",
    "domains": r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b",
    "urls":    r"https?://[^\s\"'>]+",
    "md5":     r"\b[a-fA-F0-9]{32}\b",
    "sha256":  r"\b[a-fA-F0-9]{64}\b",
    "cves":    r"CVE-\d{4}-\d{4,7}"
}

# ——— Retry-enabled HTTP session ———
session = requests.Session()
retries = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504]
)
session.mount("https://", HTTPAdapter(max_retries=retries))
session.mount("http://",  HTTPAdapter(max_retries=retries))

def load_seen_iocs():
    try:
        with open(SEEN_IOCS_FILE, "r", encoding="utf-8") as f:
            return set(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError):
        return set()

def save_seen_iocs(seen):
    with open(SEEN_IOCS_FILE, "w", encoding="utf-8") as f:
        json.dump(list(seen), f, indent=2)

def extract_iocs(text):
    return {ioc: list(set(re.findall(rx, text))) for ioc, rx in patterns.items()}

def clean_html(html):
    return BeautifulSoup(html, "html.parser").get_text()

def parse_date(entry):
    # 1) feedparser-normalized structs
    struct = entry.get("published_parsed") or entry.get("updated_parsed")
    if struct:
        return datetime(*struct[:6])
    # 2) raw string fields
    for key in ("published", "updated", "pubDate"):
        raw = entry.get(key)
        if raw:
            parsed = feedparser._parse_date(raw)
            if parsed:
                return datetime(*parsed[:6])
    return None

def is_recent(entry):
    dt = parse_date(entry)
    return bool(dt and dt >= (datetime.utcnow() - timedelta(days=DAYS_BACK)))

def detect_context(text):
    tags = set()
    lower = text.lower()
    for label, kws in IOC_KEYWORDS.items():
        for kw in kws:
            if kw in lower:
                tags.add(label)
    return list(tags)

def process_feed(url, seen_iocs):
    logging.info(f"-> Fetching feed: {url}")
    out = []
    feed = feedparser.parse(url)
    for entry in feed.entries:
        if not is_recent(entry):
            continue

        title = entry.get("title", "<no title>")
        link  = entry.get("link", "")
        pubdt = parse_date(entry)

        try:
            resp = session.get(
                link,
                headers={"User-Agent": "MISP-IOC-Collector/1.0"},
                timeout=10
            )
            text  = clean_html(resp.text)
            found = extract_iocs(text)

            dedup = {}
            for kind, vals in found.items():
                new = [v for v in vals if v not in seen_iocs]
                dedup[kind] = new
                seen_iocs.update(new)

            if any(dedup.values()):
                out.append({
                    "title":     title,
                    "source":    link,
                    "published": pubdt.isoformat() if pubdt else "",
                    "feed":      url,
                    "iocs":      dedup,
                    "tags":      detect_context(text)
                })

        except Exception as e:
            logging.error(f"Error fetching {link}: {e}")

    logging.info(f"-> {len(out)} new articles with IOCs from {url}")
    return out

def main():
    seen_iocs   = load_seen_iocs()
    all_results = []

    for rss in RSS_FEEDS:
        all_results.extend(process_feed(rss.strip(), seen_iocs))

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)

    save_seen_iocs(seen_iocs)
    logging.info(f"Wrote {len(all_results)} records to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
