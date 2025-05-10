import re

# Centralized regex patterns for IOC extraction
IOC_PATTERNS = {
    "ips": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domains": re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b"),
    "urls": re.compile(r"(?:https?|hxxp):\/\/[^\s\"'>]+"),
    "emails": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "cves": re.compile(r"\bCVE-\d{4}-\d{4,}\b"),
}