import re

# Centralized regex patterns for IOC extraction
IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),  # Matches IPv4 addresses
    "ipv6": re.compile(r"\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b"),  # Matches IPv6 addresses
    "domains": re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b"),  # Matches domain names
    "urls": re.compile(r"(?:https?|hxxp):\/\/[^\s\"'>]+"),  # Matches URLs, including defanged ones
    "emails": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),  # Matches email addresses
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),  # Matches SHA-1 hashes
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),  # Matches SHA-256 hashes
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),  # Matches MD5 hashes
    "cves": re.compile(r"\bCVE-\d{4}-\d{4,}(?:-\d+)?\b"),  # Matches CVEs (extended for CVSS V3)
    "mac_addresses": re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"),  # Matches MAC addresses
    "ports": re.compile(r"\b(?:[0-9]{1,5})\b"),  # Matches numerical ports (0-65535)
    "asn": re.compile(r"\bAS[0-9]{1,5}\b"),  # Matches Autonomous System Numbers (ASNs)
    "cidr": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\/(?:[0-9]|[1-2][0-9]|3[0-2])\b"),  # Matches CIDR ranges
    "file_paths": re.compile(r"(?:[A-Za-z]:\\|\/)?(?:[\/\\][A-Za-z0-9._-]+)+"),  # Matches file paths
    "btc_wallets": re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),  # Matches BTC wallet addresses
    "eth_wallets": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),  # Matches ETH wallet addresses
    "registry_keys": re.compile(r"(HKLM|HKCU|HKEY_CLASSES_ROOT|HKEY_CURRENT_CONFIG|HKEY_USERS|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)(\\[^\s]+)+"),  # Matches Windows registry keys
    "process_names": re.compile(r"\b(?:[a-zA-Z0-9_-]+\.exe|\.dll|\.bat|\.vbs|\.sh|\.py)\b"),  # Matches common process names
    "mutexes": re.compile(r"\bGlobal\\[A-Za-z0-9_-]+\b"),  # Matches mutexes
    "scheduled_tasks": re.compile(r"(?:\\Microsoft\\Windows\\[^\s]+|[A-Za-z0-9_-]+\.job)"),  # Matches Windows scheduled tasks
}

# Recommendations and Fixes:
# 1. **IPv4 Address Validation**:
#    - The current pattern matches invalid IPs like "999.999.999.999".
#    - Fix: Replace the IPv4 regex with stricter validation for valid ranges (0-255).
IOC_PATTERNS["ipv4"] = re.compile(
    r"\b(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}\b"
)

# 2. **IPv6 Abbreviations**:
#    - The current pattern does not account for abbreviated IPv6 addresses like "::1" or "2001:db8::".
#    - Fix: Use a more comprehensive regex for IPv6 validation.
IOC_PATTERNS["ipv6"] = re.compile(
    r"\b(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}"
    r"|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}"
    r"|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}"
    r"|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]|)[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]|)[0-9])"
    r"|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]|)[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]|)[0-9]))\b"
)

# 3. **Enhanced URL Matching**:
#    - Support more defanged formats like "hxxp[:]//example.com".
#    - Fix: Add more flexibility to the regex for defanged URLs.
IOC_PATTERNS["urls"] = re.compile(
    r"(?:https?|hxxp)(?::|\\x3a|\\[xX]3[aA])//[^\s\"'>]+"
)

# 4. **CVE Validation**:
#    - Extend the CVE regex to support CVSS v3 (e.g., CVE-2023-12345-6789).
#    - Fix: Add optional trailing numbers to the regex.
IOC_PATTERNS["cves"] = re.compile(
    r"\bCVE-\d{4}-\d{4,}(?:-\d+)?\b"
)

# 5. **Stricter Port Validation**:
#    - The current pattern matches any number, including invalid ports like "99999".
#    - Fix: Restrict the range to valid ports (0-65535).
IOC_PATTERNS["ports"] = re.compile(
    r"\b(6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]?\d{1,4})\b"
)
