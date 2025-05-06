# File: utils/enrichment.py
import requests
import re
import logging
from pathlib import Path

import spacy

# MITRE CTI JSON URL
MITRE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)

# Load spaCy model once
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    logging.error("spaCy model 'en_core_web_sm' not found. Please download it via `python -m spacy download en_core_web_sm`.")
    nlp = None

# Cache on-disk to avoid repeated downloads between runs
CACHE_FILE = Path(__file__).parent / "mitre_cache.json"
MITRE_CACHE = {
    "techniques": set(),
    "actors": set(),
    "malwares": set(),
}


def fetch_mitre_data():
    # Try loading from disk
    if CACHE_FILE.exists():
        try:
            data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
            for k, v in data.items():
                MITRE_CACHE[k] = set(v)
            return
        except Exception:
            pass

    # Otherwise fetch from network
    try:
        resp = requests.get(MITRE_URL, timeout=15)
        resp.raise_for_status()
        data = resp.json()
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
        # Persist cache to disk
        CACHE_FILE.write_text(json.dumps({k: sorted(list(v)) for k, v in MITRE_CACHE.items()}), encoding="utf-8")
    except Exception as e:
        logging.error(f"[!] Failed to fetch MITRE data: {e}")


def extract_ner(text: str) -> dict:
    if nlp is None:
        return {"actors": [], "malware": [], "mitre_techniques": [], "cves": []}

    if not MITRE_CACHE["techniques"]:
        fetch_mitre_data()

    doc = nlp(text)
    actors = set()
    malwares = set()
    techniques = set()
    cves = set(re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE))

    for ent in doc.ents:
        ent_text = ent.text.strip()
        if ent_text in MITRE_CACHE["actors"]:
            actors.add(ent_text)
        if ent_text in MITRE_CACHE["malwares"]:
            malwares.add(ent_text)
        if ent_text.upper() in MITRE_CACHE["techniques"]:
            techniques.add(ent_text.upper())

    return {
        "actors": sorted(actors),
        "malware": sorted(malwares),
        "mitre_techniques": sorted(techniques),
        "cves": sorted(cves)
    }

def enrich_with_ner(text: str) -> dict:
    """
    Enrich text using Named Entity Recognition against MITRE data.

    Returns a dict with keys: actors, malware, mitre_techniques, cves.
    """
    return extract_ner(text)