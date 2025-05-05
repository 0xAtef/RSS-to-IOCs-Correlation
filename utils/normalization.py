# File: utils/normalization.py
import re
from urllib.parse import urlparse


def normalize_ioc(ioc: str) -> str:
    ioc = ioc.strip().lower()
    # defang common patterns
    ioc = ioc.replace("[.]", ".").replace("(.)", ".").replace(" hxxp", "http")
    # strip http/s
    ioc = re.sub(r"^https?://", "", ioc)
    return ioc


def refang(ioc: str) -> str:
    return ioc.replace("[.]", ".").replace("(.)", ".").replace(" hxxp", "http")


def is_ioc_whitelisted(ioc_value: str, feed_domain: str, whitelist_by_feed: dict) -> bool:
    low = normalize_ioc(ioc_value)
    global_wl = set(whitelist_by_feed.get("*", []))
    feed_wl = set(whitelist_by_feed.get(feed_domain, []))
    combined = global_wl | feed_wl
    if low in {normalize_ioc(x) for x in combined}:
        return True
    # if domain matches feed
    try:
        domain = urlparse(low).netloc.lower()
        if domain == feed_domain:
            return True
    except Exception:
        pass
    # substring match
    if feed_domain in low:
        return True
    return False
