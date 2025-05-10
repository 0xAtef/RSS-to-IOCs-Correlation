import re
import logging
from urllib.parse import urlparse, unquote
from datetime import datetime

class IOCUtils:
    """
    Utility class for handling IOC-related operations like normalization and whitelisting.
    """

    def __init__(self, whitelist_by_feed=None):
        """
        Initialize with a whitelist dictionary.
        :param whitelist_by_feed: Dictionary containing global and feed-specific whitelists.
        """
        self.whitelist_by_feed = whitelist_by_feed or {}

    @staticmethod
    def normalize_ioc(ioc: str) -> str:
        """
        Normalize an IOC by defanging, stripping protocols, and handling common patterns.
        :param ioc: Input IOC string.
        :return: Normalized IOC string.
        """
        try:
            ioc = ioc.strip().lower()
            ioc = ioc.replace("[.]", ".").replace("(.)", ".").replace(" hxxp", "http")
            ioc = re.sub(r"^https?://", "", ioc).rstrip("/")
            ioc = unquote(ioc)
            if "/" not in ioc:
                ioc = re.sub(r"^www\.", "", ioc)
            ioc = re.sub(r"\[([0-9a-fA-F:]+)\]", r"\1", ioc)
            return ioc
        except Exception as e:
            logging.error(f"Error normalizing IOC '{ioc}': {e}")
            return ioc  # Return the original IOC in case of normalization error

    def is_ioc_whitelisted(self, ioc_value: str, feed_domain: str = "*") -> bool:
        """
        Check if an IOC is whitelisted based on global and feed-specific whitelists.
        :param ioc_value: The IOC value to check.
        :param feed_domain: The feed domain for feed-specific whitelist checks.
        :return: True if the IOC is whitelisted, False otherwise.
        """
        try:
            normalized_ioc = self.normalize_ioc(ioc_value)
            global_whitelist = {self.normalize_ioc(x) for x in self.whitelist_by_feed.get("*", [])}
            feed_whitelist = {self.normalize_ioc(x) for x in self.whitelist_by_feed.get(feed_domain, [])}
            combined_whitelist = global_whitelist | feed_whitelist

            # Exact match check
            if normalized_ioc in combined_whitelist:
                return True

            # Domain match
            parsed_ioc = urlparse(normalized_ioc)
            ioc_domain = parsed_ioc.netloc.lower() if parsed_ioc.netloc else normalized_ioc
            for whitelist_domain in combined_whitelist:
                if whitelist_domain in ioc_domain or ioc_domain.endswith(f".{whitelist_domain}"):
                    return True

            # Substring match
            for whitelist_domain in combined_whitelist:
                if whitelist_domain in normalized_ioc:
                    return True
        except Exception as e:
            logging.warning(f"Error processing IOC '{ioc_value}' in feed_domain '{feed_domain}': {e}")

        return False

    def validate_ioc(self, ioc_value: str, ioc_type: str) -> bool:
        """
        Validate an IOC against its type's regex pattern.
        :param ioc_value: The IOC value to validate.
        :param ioc_type: The IOC type (e.g., 'ipv4s', 'urls').
        :return: True if the IOC matches the type's regex, False otherwise.
        """
        from utils.regex_patterns import IOC_PATTERNS  # Prevent circular dependency
        pattern = IOC_PATTERNS.get(ioc_type)
        if not pattern:
            logging.warning(f"No regex pattern found for IOC type '{ioc_type}'")
            return False
        return bool(pattern.match(ioc_value))

    @staticmethod
    def log_ioc_processing(ioc: str, is_whitelisted: bool):
        """
        Log IOC processing details.
        :param ioc: The IOC being processed.
        :param is_whitelisted: Whether the IOC is whitelisted or not.
        """
        status = "WHITELISTED" if is_whitelisted else "NOT WHITELISTED"
        logging.info(f"[{datetime.utcnow().isoformat()}] Processed IOC: {ioc} - Status: {status}")

    def log_failed_normalization(self, ioc: str):
        """
        Log failed normalization attempts for debugging purposes.
        :param ioc: The IOC that could not be normalized.
        """
        logging.warning(f"[{datetime.utcnow().isoformat()}] Failed to normalize IOC: {ioc}")