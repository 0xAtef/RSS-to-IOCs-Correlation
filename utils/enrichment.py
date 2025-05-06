# File: utils/enrichment.py
import requests
import re
import logging
from pathlib import Path
import hashlib
import json
import spacy

# MITRE CTI JSON URL
MITRE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)

# Load spaCy model once
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    logging.warning("spaCy model 'en_core_web_sm' not found. Attempting to download...")
    try:
        import subprocess
        subprocess.run(["python", "-m", "spacy", "download", "en_core_web_sm"], check=True)
        nlp = spacy.load("en_core_web_sm")
    except Exception as e:
        logging.error(f"Failed to download spaCy model: {e}")
        nlp = None

# Cache on-disk to avoid repeated downloads between runs
CACHE_FILE = Path(__file__).parent / "mitre_cache.json"
MITRE_CACHE = {
    "techniques": set(),
    "actors": set(),
    "malwares": set(),
    "tools": set(),
    "campaigns": set(),
}


def fetch_mitre_data():
    # Try loading from disk
    if CACHE_FILE.exists():
        try:
            data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
            for k, v in data.items():
                MITRE_CACHE[k] = set(v)
            logging.info("Loaded MITRE data from cache.")
            return
        except Exception as e:
            logging.warning(f"Failed to load MITRE cache: {e}")

    # Otherwise fetch from network
    try:
        for attempt in range(3):  # Retry logic
            try:
                resp = requests.get(MITRE_URL, timeout=15)
                resp.raise_for_status()
                data = resp.json()
                break
            except requests.exceptions.Timeout:
                logging.warning(f"Timeout fetching MITRE data (attempt {attempt + 1}/3). Retrying...")
            except requests.exceptions.RequestException as e:
                logging.error(f"Request error: {e}")
                return
        else:
            logging.error("Failed to fetch MITRE data after 3 attempts.")
            return

        # Process data
        for obj in data.get("objects", []):
            t = obj.get("type")
            if t == "attack-pattern":
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack" and "external_id" in ref:
                        MITRE_CACHE["techniques"].add(ref["external_id"].upper())
            elif t == "intrusion-set":
                MITRE_CACHE["actors"].add(obj.get("name", ""))
                for alias in obj.get("aliases", []):
                    MITRE_CACHE["actors"].add(alias)
            elif t == "malware":
                MITRE_CACHE["malwares"].add(obj.get("name", ""))
                for alias in obj.get("aliases", []):
                    MITRE_CACHE["malwares"].add(alias)
            elif t == "tool":
                MITRE_CACHE["tools"].add(obj.get("name", ""))
                for alias in obj.get("aliases", []):
                    MITRE_CACHE["tools"].add(alias)
            elif t == "campaign":
                MITRE_CACHE["campaigns"].add(obj.get("name", ""))

        # Compute hash of fetched data
        fetched_hash = hashlib.md5(json.dumps(data).encode("utf-8")).hexdigest()
        if CACHE_FILE.exists():
            cached_hash = hashlib.md5(CACHE_FILE.read_bytes()).hexdigest()
            if fetched_hash == cached_hash:
                logging.info("MITRE data unchanged. Skipping cache update.")
                return

        # Persist cache to disk
        CACHE_FILE.write_text(json.dumps({k: sorted(list(v)) for k, v in MITRE_CACHE.items()}), encoding="utf-8")
        logging.info("MITRE data fetched and cached successfully.")
    except Exception as e:
        logging.error(f"[!] Failed to fetch MITRE data: {e}")


def extract_ner(text: str) -> dict:
    if nlp is None:
        return {"actors": [], "malware": [], "mitre_techniques": [], "cves": [], "tools": [], "campaigns": []}

    if not MITRE_CACHE["techniques"]:
        fetch_mitre_data()

    doc = nlp(text)
    actors = set()
    malwares = set()
    techniques = set()
    tools = set()
    campaigns = set()
    cves = set(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, flags=re.IGNORECASE))

    for ent in doc.ents:
        ent_text = ent.text.strip().lower()
        if ent_text in {actor.lower() for actor in MITRE_CACHE["actors"]}:
            actors.add(ent_text)
        if ent_text in {malware.lower() for malware in MITRE_CACHE["malwares"]}:
            malwares.add(ent_text)
        if ent_text.upper() in MITRE_CACHE["techniques"]:
            techniques.add(ent_text.upper())
        if ent_text in {tool.lower() for tool in MITRE_CACHE["tools"]}:
            tools.add(ent_text)
        if ent_text in {campaign.lower() for campaign in MITRE_CACHE["campaigns"]}:
            campaigns.add(ent_text)

    return {
        "actors": sorted(actors),
        "malware": sorted(malwares),
        "mitre_techniques": sorted(techniques),
        "cves": sorted(cves),
        "tools": sorted(tools),
        "campaigns": sorted(campaigns),
    }


def enrich_with_ner(text: str) -> dict:
    """
    Enrich text using Named Entity Recognition against MITRE data.

    Returns a dict with keys: actors, malware, mitre_techniques, cves, tools, campaigns.
    """
    return extract_ner(text)