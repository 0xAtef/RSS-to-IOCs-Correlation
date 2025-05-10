import requests
import logging

def check_feed_health(feed_url, timeout=10,log_file=None):
    """
    Check the health of an RSS feed URL.

    Args:
        feed_url (str): The URL of the RSS feed to check.
        timeout (int): Timeout duration for the request in seconds.

    Returns:
        bool: True if the feed is healthy, False otherwise.
    """
    logging.info(f"Checking health for feed URL: {feed_url}")
    try:
        # Attempt with HEAD request
        response = requests.head(feed_url, timeout=timeout, allow_redirects=True)
        if response.status_code == 200:
            logging.info(f"Feed URL is healthy: {feed_url}")
            return True
        elif 300 <= response.status_code < 400:
            logging.warning(f"Feed URL redirected: {feed_url}. Status code: {response.status_code}")
        else:
            logging.warning(f"Feed URL returned non-200 status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        logging.warning(f"HEAD request failed for {feed_url}: {e}")

    # Fallback to GET request
    logging.info(f"Falling back to GET request for feed URL: {feed_url}")
    try:
        response = requests.get(feed_url, timeout=timeout, allow_redirects=True)
        if response.status_code == 200:
            logging.info(f"Feed URL is healthy with GET: {feed_url}")
            return True
        elif 300 <= response.status_code < 400:
            logging.warning(f"Feed URL redirected: {feed_url}. Status code: {response.status_code}")
        else:
            logging.warning(f"Feed URL returned non-200 status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        logging.error(f"GET request failed for {feed_url}: {e}")

    return False