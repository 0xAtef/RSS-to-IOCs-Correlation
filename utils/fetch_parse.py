import logging
import feedparser
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime, timedelta
from utils.normalization import normalize_ioc, is_ioc_whitelisted
from utils.enrichment import enrich_with_ner
from utils.translator import translate_to_english

def fetch_feed(feed_url, session, cfg):
    """Fetch the RSS feed and return the parsed content."""
    try:
        logging.info(f"Fetching {feed_url}")
        response = session.get(feed_url, timeout=cfg.get("request_timeout", 10),
                               headers={"User-Agent": cfg.get("user_agent")})
        response.raise_for_status()
        return feedparser.parse(response.text)
    except requests.exceptions.RequestException as exc:
        logging.error(f"Error fetching {feed_url}: {exc}")
        return None


def process_feed(feed_url, seen, global_seen, session, cfg, ioc_patterns, whitelist_by_feed, max_days_old):
    """Process a single feed URL and extract IOCs."""
    logging.info(f"Starting to process feed: {feed_url}")
    
    # Fetch the feed
    feed = fetch_feed(feed_url, session, cfg)
    if not feed or not feed.entries:
        logging.warning(f"No entries found in {feed_url}")
        return []

    def strip_html(html):
        """Remove HTML tags from the text."""
        return BeautifulSoup(html, "html.parser").get_text()

    def parse_date(e):
        """Parse the publication date of a feed entry."""
        sd = e.get("published_parsed") or e.get("updated_parsed")
        if sd:
            return datetime(*sd[:6])
        return None

    def recent(e):
        """Check if the feed entry is recent based on the max_days_old setting."""
        d = parse_date(e)
        return bool(d and d >= datetime.utcnow() - timedelta(days=max_days_old))

    out = []
    for e in feed.entries:
        title = e.get("title", "No Title")
        link = e.get("link", "")
        logging.info(f"Processing entry: {title}")

        # Skip old entries
        if not recent(e):
            logging.info(f"Skipping old entry: {title}")
            continue

        # Fetch the article content
        try:
            logging.info(f"Fetching article: {link}")
            r = session.get(link, timeout=cfg.get("request_timeout", 10),
                            headers={"User-Agent": cfg.get("user_agent")})
            r.raise_for_status()
            text = strip_html(r.text)
        except requests.exceptions.RequestException as exc:
            logging.error(f"Error fetching article {link}: {exc}")
            continue

        # Extract IOCs
        raw = extract_iocs(text, ioc_patterns)
        filtered = {}
        for typ, vals in raw.items():
            keep = []
            for v in vals:
                n = normalize_ioc(v)
                if n in seen or n in global_seen or is_ioc_whitelisted(v, urlparse(feed_url).netloc, whitelist_by_feed):
                    continue
                global_seen.add(n)  # Add to global seen set
                seen.add(n)  # Add to feed-specific seen set
                keep.append(v)
            filtered[typ] = keep

        # Skip entries with no IOCs
        if not any(filtered.values()):
            logging.info(f"No IOCs found in entry: {title}")
            continue

        # Enrich the text with NER
        enrichment = enrich_with_ner(text)

        # Translate the title to English if necessary
        translated_title = translate_to_english(title)

        # Add the processed entry to the output
        out.append({
            "id": str(uuid.uuid4()),
            "title": translated_title,
            "source": link,
            "published": (parse_date(e) or datetime.utcnow()).isoformat(),
            "feed": feed_url,
            "iocs": filtered,
            "tags": context_tags(text, feed_url, cfg),
            "enrichment": enrichment  # Add enrichment data
        })

        logging.info(f"Processed entry: {translated_title}")
        logging.info(f"Extracted IOCs: {filtered}")
        out.append({
            # Existing logic for appending processed entries...
        })

    logging.info(f"Finished processing feed: {feed_url}. Total entries processed: {len(out)}")
    return out


def extract_iocs(text, ioc_patterns):
    """Extract IOCs from the given text using regex patterns."""
    extracted = {}
    for ioc_type, pattern in ioc_patterns.items():
        matches = re.findall(pattern, text)
        if matches:
            logging.info(f"Extracted {len(matches)} {ioc_type}(s): {matches}")
        extracted[ioc_type] = matches
    return extracted


def context_tags(text, feed_url, cfg):
    """
    Generate context tags for the feed.
    Dynamically generate tags based on content, feed metadata, and IOC types.
    """
    tags = set(cfg.get("fixed_tags", []))  # Start with fixed tags from config

    # Convert text to lowercase for keyword matching
    lt = text.lower()

    # Add tags based on IOC context keywords
    for ctx, kws in cfg.get("ioc_context_keywords", {}).items():
        if any(k in lt for k in kws):
            tags.add(f"context:{ctx}")

    # Add tags based on feed-specific tags
    feed_tags = cfg.get("feed_tags_by_feed", {}).get(feed_url, [])
    tags.update(feed_tags)

    # Add IOC type tags (e.g., ip, domain, url, md5, sha256, etc.)
    if "ip" in lt:
        tags.add("ioc:type:ip")
    if "domain" in lt:
        tags.add("ioc:type:domain")
    if "url" in lt:
        tags.add("ioc:type:url")
    if "md5" in lt:
        tags.add("ioc:type:md5")
    if "sha1" in lt:
        tags.add("ioc:type:sha1")
    if "sha256" in lt:
        tags.add("ioc:type:sha256")
    if "email" in lt:
        tags.add("ioc:type:email")
    if "filename" in lt:
        tags.add("ioc:type:filename")
    if "cve" in lt:
        tags.add("ioc:type:cve")

    # Add tags for feed metadata
    tags.add(f"feed:source:{urlparse(feed_url).netloc}")
    tags.add(f"feed:published:{datetime.utcnow().strftime('%Y-%m-%d')}")

    # Standardize tags for MISP
    standardized_tags = {tag.replace(" ", "_").lower() for tag in tags}

    return list(standardized_tags)