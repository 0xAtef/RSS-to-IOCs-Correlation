# File: utils/normalization.py
import re
from urllib.parse import urlparse, unquote
import logging


def normalize_ioc(ioc: str) -> str:
    """
    Normalize an IOC by defanging, stripping protocols, and handling common patterns.
    """
    ioc = ioc.strip().lower()
    # Defang common patterns
    ioc = ioc.replace("[.]", ".").replace("(.)", ".").replace(" hxxp", "http")
    # Strip http/s
    ioc = re.sub(r"^https?://", "", ioc)
    # Remove trailing slashes
    ioc = ioc.rstrip("/")
    # Decode URL-encoded characters
    ioc = unquote(ioc)
    # Remove "www." prefix from domains
    if "/" not in ioc:  # Likely a domain
        ioc = re.sub(r"^www\.", "", ioc)
    # Normalize IPv6 brackets
    ioc = re.sub(r"\[([0-9a-fA-F:]+)\]", r"\1", ioc)
    return ioc


def refang(ioc: str) -> str:
    """
    Refang an IOC by replacing defanged patterns with their original forms.
    """
    return (
        ioc.replace("[.]", ".")
        .replace("(.)", ".")
        .replace(" hxxp", "http")
        .replace("{dot}", ".")
        .replace("[dot]", ".")
        .replace("(dot)", ".")
    )


def is_ioc_whitelisted(ioc_value: str, feed_domain: str, whitelist_by_feed: dict) -> bool:
    """
    Check if an IOC is whitelisted based on global and feed-specific whitelists.
    """
    low = normalize_ioc(ioc_value)
    logging.debug(f"Normalized IOC: {low}")
    global_wl = {normalize_ioc(x) for x in whitelist_by_feed.get("*", [])}
    feed_wl = {normalize_ioc(x) for x in whitelist_by_feed.get(feed_domain, [])}
    combined = global_wl | feed_wl

    # Exact match
    if low in combined:
        logging.debug(f"IOC '{ioc_value}' is whitelisted (exact match).")
        return True

    # Domain match (including subdomains)
    try:
        domain = urlparse(low).netloc.lower()
        if domain == feed_domain or domain.endswith(f".{feed_domain}"):
            logging.debug(f"IOC '{ioc_value}' is whitelisted (domain match).")
            return True
    except Exception as e:
        logging.warning(f"Error parsing domain from IOC '{ioc_value}': {e}")

    # Substring match
    if feed_domain in low:
        logging.debug(f"IOC '{ioc_value}' is whitelisted (substring match).")
        return True

    logging.debug(f"IOC '{ioc_value}' is NOT whitelisted.")
    return False
