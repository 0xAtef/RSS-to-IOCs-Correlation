import logging
import feedparser
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime, timedelta
from utils.normalization import normalize_ioc, is_ioc_whitelisted
from utils.enrichment import enrich_with_ner

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
    feed = fetch_feed(feed_url, session, cfg)
    if not feed or not feed.entries:
        logging.warning(f"No entries found in {feed_url}")
        return []

    def strip_html(html):
        return BeautifulSoup(html, "html.parser").get_text()

    def parse_date(e):
        sd = e.get("published_parsed") or e.get("updated_parsed")
        if sd:
            return datetime(*sd[:6])
        return None

    def recent(e):
        d = parse_date(e)
        return bool(d and d >= datetime.utcnow() - timedelta(days=max_days_old))

    out = []
    for e in feed.entries:
        if not recent(e):
            continue

        link = e.get("link", "")
        try:
            r = session.get(link, timeout=cfg.get("request_timeout", 10),
                            headers={"User-Agent": cfg.get("user_agent")})
            r.raise_for_status()
            text = strip_html(r.text)
        except requests.exceptions.RequestException as exc:
            logging.error(f"Error fetching article {link}: {exc}")
            continue

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

        if not any(filtered.values()):
            continue

        # Enrich the text with NER
        enrichment = enrich_with_ner(text)

        out.append({
            "id": str(uuid.uuid4()),
            "title": e.get("title", ""),
            "source": link,
            "published": (parse_date(e) or datetime.utcnow()).isoformat(),
            "feed": feed_url,
            "iocs": filtered,
            "tags": context_tags(text, feed_url, cfg),
            "enrichment": enrichment  # Add enrichment data
        })

    logging.info(f"Found {len(out)} new entries in {feed_url}")
    return out


def extract_iocs(text, ioc_patterns):
    """Extract IOCs from text using regex patterns."""
    clean = text.replace("\n", " ")
    return {t: list({m for m in re.findall(pat, clean)}) for t, pat in ioc_patterns.items()}


def context_tags(text, feed_url, cfg):
    """Generate context tags for the feed."""
    tags = set(cfg.get("fixed_tags", []))
    lt = text.lower()
    for ctx, kws in cfg.get("ioc_context_keywords", {}).items():
        if any(k in lt for k in kws):
            tags.add(ctx)
    tags.update(cfg.get("feed_tags_by_feed", {}).get(feed_url, []))
    return list(tags)