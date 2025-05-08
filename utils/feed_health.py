import logging
import requests

def monitor_feed_health(url, session, log_file, retries=3):
    """
    Check the health of an RSS feed URL and log the results.

    Args:
        url (str): The RSS feed URL to check.
        session (requests.Session): The HTTP session for making requests.
        log_file (str): Path to the log file.
        retries (int): Number of times to retry checking the feed health.

    Returns:
        bool: True if the feed is healthy, False otherwise.
    """
    retries = int(retries)  # Ensure retries is an integer
    for attempt in range(retries):
        try:
            response = session.head(url, timeout=5)
            if response.status_code == 200:
                logging.info(f"Feed is healthy: {url}")
                return True
            else:
                logging.warning(f"Feed returned status code {response.status_code}: {url}")
        except requests.RequestException as e:
            logging.warning(f"Attempt {attempt + 1}/{retries} failed for feed: {url}. Error: {e}")
    logging.error(f"Feed is unhealthy after {retries} retries: {url}")
    return False