# utils/normalization.py
import re
from urllib.parse import urlparse

def normalize_ioc(ioc):
    ioc = ioc.strip().lower()
    ioc = re.sub(r"^https?://", "", ioc)
    return ioc

def refang(ioc):
    return ioc.replace("[.]", ".").replace("(.)", ".").replace(" hxxp", "http")

def is_ioc_whitelisted(ioc_value, feed_domain, whitelist_by_feed):
    low = normalize_ioc(ioc_value)
    global_wl = set(whitelist_by_feed.get("*", []))
    feed_wl = set(whitelist_by_feed.get(feed_domain, []))
    combined_wl = global_wl | feed_wl
    if low in combined_wl:
        return True
    try:
        if urlparse(low).netloc.lower() == feed_domain:
            return True
    except:
        pass
    if feed_domain in low:
        return True
    return False
