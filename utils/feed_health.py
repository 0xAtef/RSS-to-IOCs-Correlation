import logging
import requests

def monitor_feed_health(feed_url, session, retries=3):
    """
    Check the health of an RSS feed with retries.
    """
    for attempt in range(retries):
        try:
            response = session.head(feed_url, timeout=5)
            response.raise_for_status()
            logging.info(f"Feed {feed_url} is healthy. Status: {response.status_code}, Response Time: {response.elapsed.total_seconds()}s")
            return True
        except requests.exceptions.RequestException as exc:
            logging.warning(f"Attempt {attempt + 1}/{retries} - Feed {feed_url} is unhealthy: {exc}")
    return False