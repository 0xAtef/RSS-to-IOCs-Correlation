import feedparser
import requests
from bs4 import BeautifulSoup
import re
import json
from datetime import datetime, timedelta
import time

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

IOC_KEYWORDS = {
    "c2": ["command and control", "c2 server", "beacon", "callback", "control channel", "cnc", "command channel"],
    "payload": ["payload", "dropper", "executable", "binary", "installer", "installer payload", "stub"],
    "malware": ["malware", "ransomware", "trojan", "worm", "backdoor", "spyware", "adware", "rootkit"],
    "phishing": ["phishing", "spearphishing", "credential theft", "spoofing", "malicious link", "fake login"],
    "exploit": ["exploit", "vulnerability", "zeroday", "buffer overflow", "heap spray", "remote code execution", "CVE-"],
    "ddos": ["denial of service", "dos attack", "ddos", "flood", "amplification", "botnet"],
    "botnet": ["botnet", "zombie", "drone", "bot herder", "command hub"],
    "crypto": ["cryptomining", "coinminer", "mining malware", "cryptojacker", "coinhive"],
    "credential": ["password", "credentials", "login", "auth token", "two-factor", "2fa", "otp", "session cookie"],
    "injection": ["sql injection", "xss", "cross-site scripting", "code injection", "command injection"],
    "fraud": ["fraud", "scam", "social engineering", "business email compromise", "impersonation"]
}

patterns = {
    "ips": r"(?:\d{1,3}\.){3}\d{1,3}",
    "domains": r"\b(?:[a-zA-Z0-9-]+\.)+[A-Za-z]{2,}\b",
    "urls": r"https?://[^\s\"'>]+",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "cves": r"CVE-\d{4}-\d{4,7}"
}

def extract_iocs(text):
    return {ioc: list(set(re.findall(regex, text))) for ioc, regex in patterns.items()}

def clean_html(html):
    return BeautifulSoup(html, "html.parser").get_text()

def parse_date(entry):
    """
    Return a datetime (UTC) for the entry by trying multiple date fields.
    """
    # 1) Normalized structs from feedparser (UTC)
    struct = entry.get("published_parsed") or entry.get("updated_parsed")
    if struct:
        return datetime(*struct[:6])

    # 2) Raw string fields: published, updated, then pubDate
    for key in ("published", "updated", "pubDate"):
        raw = entry.get(key)
        if raw:
            parsed = feedparser._parse_date(raw)
            if parsed:
                return datetime(*parsed[:6])
    return None

def is_recent(entry, days=1):
    """
    Return True if entry date is within the last `days` days.
    """
    dt = parse_date(entry)
    if not dt:
        return False
    return dt >= (datetime.utcnow() - timedelta(days=days))

def detect_context(text):
    tags = set()
    lower = text.lower()
    for label, kws in IOC_KEYWORDS.items():
        for kw in kws:
            if kw in lower:
                tags.add(label)
    return list(tags)

def process_feed(url, global_seen):
    results = []
    feed = feedparser.parse(url)
    for entry in feed.entries:
        if not is_recent(entry):
            continue

        article = {
            "title": entry.get("title", ""),
            "source": entry.get("link", ""),
            "published": (parse_date(entry) or "").isoformat(),
            "feed": url,
            "iocs": {},
            "tags": []
        }
        try:
            resp = requests.get(
                entry.link,
                headers={"User-Agent": "MISP-IOC-Collector/1.0"},
                timeout=10
            )
            text = clean_html(resp.text)
            found = extract_iocs(text)

            deduped = {}
            for kind, vals in found.items():
                new_vals = [v for v in vals if v not in global_seen]
                deduped[kind] = new_vals
                global_seen.update(new_vals)

            article["iocs"] = deduped
            article["tags"] = detect_context(text)

            if any(deduped.values()):
                results.append(article)

        except Exception as e:
            article["error"] = str(e)
            results.append(article)

    return results

def main():
    all_results = []
    seen_iocs = set()
    for rss in RSS_FEEDS:
        rss = rss.strip()
        all_results.extend(process_feed(rss, seen_iocs))

    with open("output.json", "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)
    print(f"Wrote {len(all_results)} records to output.json")

if __name__ == "__main__":
    main()
