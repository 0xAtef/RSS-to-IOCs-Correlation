import logging
import feedparser
import requests
import re
import uuid

from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime, timedelta

from utils.ioc_utils import IOCUtils
from utils.translator import translate_to_english
from utils.regex_patterns import IOC_PATTERNS
from utils.enrichment import enrich_with_ner_and_scoring as enrich_with_ner

def extract_iocs(text):
    """Extract IOCs from the given text using regex patterns."""
    extracted = {}
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            logging.info(f"Extracted {len(matches)} {ioc_type}(s): {matches}")
        extracted[ioc_type] = matches
    return extracted

def fetch_feed(feed_url, session, cfg):
    """Fetch the RSS feed."""
    try:
        headers = {"User-Agent": cfg.get("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:114.0) Gecko/20100101 Firefox/114.0")}
        logging.info(f"Fetching {feed_url}")
        response = session.get(feed_url, headers=headers, timeout=cfg.get("request_timeout", 10))
        response.raise_for_status()
        return feedparser.parse(response.text)
    except requests.exceptions.RequestException as exc:
        logging.error(f"Error fetching {feed_url}: {exc}")
        return None

def process_feed(feed_url, seen, global_seen, session, cfg, ioc_patterns, whitelist_by_feed, max_days_old):
    """
    Process a single feed and extract IOCs.

    Args:
        feed_url (str): Feed URL.
        seen (set): Set of seen IOCs.
        global_seen (set): Global set of IOCs.
        session (requests.Session): HTTP session.
        cfg (dict): Configuration dictionary.
        ioc_patterns (dict): IOC patterns for matching.
        whitelist_by_feed (dict): Whitelist for specific feeds.
        max_days_old (int): Maximum age of articles to process.
    """
    logging.info(f"Starting to process feed: {feed_url}")
    
    # Initialize IOCUtils instance
    ioc_utils = IOCUtils(whitelist_by_feed)

    # Fetch the feed
    feed = fetch_feed(feed_url, session, cfg)
    if not feed or not feed.entries:
        logging.warning(f"No entries found in {feed_url}")
        return []

    def strip_html(html):
        """Remove HTML tags from the text."""
        return BeautifulSoup(html, "html.parser").get_text()

    def parse_date(e):
        """Parse the publication date of a feed entry."""
        sd = e.get("published_parsed") or e.get("updated_parsed")
        if sd:
            return datetime(*sd[:6])
        return None

    def recent(e, max_days_old):
        """Check if the feed entry is recent based on the max_days_old setting."""
        d = parse_date(e)
        if not d:
            return False
        is_recent = d >= datetime.utcnow() - timedelta(days=max_days_old)
        if not is_recent:
            logging.info(f"Skipping old entry: {e.get('title', 'No Title')}")
        return is_recent

    out = []
    for e in feed.entries:
        title = e.get("title", "No Title")
        link = e.get("link", "")
        logging.info(f"Processing entry: {title}")

        # Skip old entries
        if not recent(e, max_days_old):
            continue

        # Fetch the article content
        try:
            logging.info(f"Fetching article: {link}")
            r = session.get(link, timeout=cfg.get("request_timeout", 10),
                            headers={"User-Agent": cfg.get("user_agent")})
            r.raise_for_status()
            text = strip_html(r.text)
        except requests.exceptions.RequestException as exc:
            logging.error(f"Error fetching article {link}: {exc}")
            continue

        # Extract IOCs
        raw = extract_iocs(text)
        filtered = {}
        for typ, vals in raw.items():
            keep = []
            for v in vals:
                n = ioc_utils.normalize_ioc(v)
                # Check if the IOC is whitelisted
                if n in seen or n in global_seen or ioc_utils.is_ioc_whitelisted(v, urlparse(feed_url).netloc):
                    continue
                global_seen.add(n)  # Add to global seen set
                seen.add(n)  # Add to feed-specific seen set
                keep.append(v)
            filtered[typ] = keep

        # Skip entries with no IOCs
        if not any(filtered.values()):
            continue

        # Enrich the text with NER
        enrichment = enrich_with_ner(text)

        # Translate the title to English if necessary
        translated_title = translate_to_english(title) if title else "No Title"

        # Add the processed entry to the output
        out.append({
            "id": str(uuid.uuid4()),
            "title": translated_title,
            "source": link,
            "published": (parse_date(e) or datetime.utcnow()).isoformat(),
            "feed": feed_url,
            "iocs": filtered,
            "tags": context_tags(text, feed_url, cfg),
            "enrichment": enrichment
        })

        logging.info(f"Processed entry: {translated_title}")
        logging.info(f"Extracted IOCs: {filtered}")
        logging.debug(f"Processed entry: {out}")

    logging.info(f"Finished processing feed: {feed_url}. Total entries processed: {len(out)}")
    return out

def context_tags(text, feed_url, cfg):
    """Generate context-based tags for the given text."""
    tags = []

    # Add fixed tags from the configuration
    tags.extend(cfg.get("fixed_tags", []))

    # Add feed-specific tags
    for feed, feed_tags in cfg.get("feed_tags_by_feed", {}).items():
        if feed in feed_url:
            tags.extend(feed_tags)

    # Expanded mapping of keywords to tags
    keyword_to_tag_mapping = {
        # General
        "cybersecurity": "Cybersecurity",

        # Threat Types
        "ransom": "Ransomware",
        "ransomware": "Ransomware",
        ".locked": "Ransomware",
        "malware": "Malware",
        "trojan": "Malware",
        "virus": "Malware",
        "worm": "Malware",
        "mining malware": "Malware",
        "spyware": "Spyware",
        "keylogger": "Spyware",
        "credential harvesting": "Spyware",
        "adware": "Adware",
        "unwanted ads": "Adware",
        "pop-up malware": "Adware",
        "botnet": "Botnet",
        "c&c botnet": "Botnet",
        "ddos botnet": "Botnet",
        "cryptojacking": "Cryptojacking",
        "unauthorized mining": "Cryptojacking",
        "coinminer": "Cryptojacking",
        "data breach": "Data Breach",
        "info leak": "Data Breach",
        "exfiltration": "Data Breach",
        "leaked credentials": "Data Breach",
        "exposed database": "Data Breach",
        "supply chain compromise": "Supply Chain Attack",
        "third-party breach": "Supply Chain Attack",
        "software dependency attack": "Supply Chain Attack",
        "lolbin": "Living Off The Land",
        "living-off-the-land binaries": "Living Off The Land",
        "fileless attack": "Living Off The Land",

        # TTPs (Tactics, Techniques & Procedures)
        "exploit": "Exploitation",
        "exploitation": "Exploitation",
        "zero-day": "Zero-Day Exploit",
        "buffer overflow": "Buffer Overflow",
        "cve-": "Vulnerability",
        "privilege escalation": "Privilege Escalation",
        "uac bypass": "Privilege Escalation",
        "token impersonation": "Privilege Escalation",
        "rce": "Remote Code Execution",
        "remote code execution": "Remote Code Execution",
        "command injection": "Remote Code Execution",
        "command and control": "C2",
        "c2": "C2",
        "c2 server": "C2",
        "beaconing": "C2",
        "heartbeat": "C2",
        "psexec": "Lateral Movement",
        "wmi lateral": "Lateral Movement",
        "smb pivot": "Lateral Movement",
        "pass-the-hash": "Lateral Movement",
        "registry autorun": "Persistence",
        "scheduled task": "Persistence",
        "startup folder": "Persistence",
        "obfuscation": "Defense Evasion",
        "encryption": "Defense Evasion",
        "anti-debug": "Defense Evasion",
        "code signing abuse": "Defense Evasion",
        "credential dumping": "Credential Access",
        "mimikatz": "Credential Access",
        "hash dump": "Credential Access",
        "port scan": "Network Reconnaissance",
        "network discovery": "Network Reconnaissance",
        "arp spoofing": "Network Reconnaissance",
        "keylogging": "Data Collection",
        "screen capture": "Data Collection",
        "audio capture": "Data Collection",

        # Actors & Campaigns
        "threat actor": "Threat Actor",
        "apt group": "APT Group",
        "apt1": "APT Group",
        "apt28": "APT Group",
        "fancy bear": "APT Group",
        "nation-state actor": "Nation-State Actor",
        "insider threat": "Insider Threat",
        "malicious insider": "Insider Threat",
        "rogue employee": "Insider Threat",
        "data saboteur": "Insider Threat",
        "espionage": "Cyber Espionage",
        "intel gathering": "Cyber Espionage",
        "info ops": "Cyber Espionage",

        # Infrastructure & Assets
        "iot": "IoT",
        "iot botnet": "IoT Botnet",
        "connected device": "Connected Device",
        "smart camera": "IoT",
        "dvr botnet": "IoT Botnet",
        "cloud misconfiguration": "Cloud",
        "container escape": "Container",
        "aws s3 public": "Cloud",
        "azure blob leak": "Cloud",
        "sqli": "Web/Application",
        "xss": "Web/Application",
        "ssrf": "Web/Application",
        "api abuse": "Web/Application",
        "web shell": "Web/Application",
        "mobile malware": "Mobile",
        "android rat": "Mobile",
        "ios jailbreak exploit": "Mobile",

        # Impact & Indicators
        "dos": "DoS",
        "ddos": "DDoS",
        "denial-of-service": "DoS",
        "syn flood": "DDoS",
        "information disclosure": "Information Disclosure",
        "malvertising": "Malvertising",
        "fake domain": "Malvertising",
        "typosquatting": "Typosquatting",

        # Defensive & Reference
        "security advisory": "Security Advisory",
        "vendor bulletin": "Security Advisory",
        "patch notice": "Security Advisory",
        "cve-": "CVE",
        "hash": "IOC",
        "ip indicator": "IOC",
        "domain": "IOC",
        "url": "IOC",
        "email address": "IOC",
        "snort": "Detection Rule",
        "suricata": "Detection Rule",
        "sigma": "Detection Rule",
        "yara": "Detection Rule",
}

    # Add tags based on the content of the text
    for keyword, tag in keyword_to_tag_mapping.items():
        if keyword in text.lower():
            tags.append(tag)

    # Remove duplicates and return
    return list(set(tags))