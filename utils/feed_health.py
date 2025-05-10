import requests
import logging

def check_feed_health(feed_url, session=None, timeout=10, log_file=None):
    """
    Check the health of an RSS feed URL.

    Args:
        feed_url (str): The URL of the RSS feed to check.
        session (requests.Session, optional): HTTP session for making requests.
        timeout (int): Timeout duration for the request in seconds.
        log_file (str, optional): Path to the log file (if logging to file is required).

    Returns:
        bool: True if the feed is healthy, False otherwise.
    """
    # Configure logging to file if a log_file is provided
    if log_file:
        logging.basicConfig(filename=log_file, level=logging.INFO, 
                            format='%(asctime)s - %(levelname)s - %(message)s')

    logging.info(f"Checking health for feed URL: {feed_url}")
    
    # Validate timeout
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        logging.error(f"Invalid timeout value: {timeout}. Must be a positive number.")
        return False

    # Use the provided session or create a new one
    http_client = session or requests

    try:
        # Attempt with HEAD request
        response = http_client.head(feed_url, timeout=timeout, allow_redirects=True)
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
        response = http_client.get(feed_url, timeout=timeout, allow_redirects=True)
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