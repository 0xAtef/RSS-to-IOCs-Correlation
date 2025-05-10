import re
import requests
import logging
from pathlib import Path
import hashlib
import json
import spacy
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import IOC_PATTERNS from regex_patterns
from utils.regex_patterns import IOC_PATTERNS
from utils.calculate_risk_score import calculate_risk_score

# MITRE CTI JSON URL
MITRE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)

# AlienVault OTX API Base URL
OTX_API_BASE_URL = "https://otx.alienvault.com/api/v1/indicators"
OTX_API_KEY = os.getenv("OTX_API_KEY")

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
        logging.error(f"Failed to download SpaCy model: {e}")
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

    # Otherwise fetch from the network
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

def fetch_otx_data(ioc: str, ioc_type: str, section: str = '') -> dict:
    try:
        endpoint = f"{OTX_API_BASE_URL}/{ioc_type}/{ioc}"
        if section:
            endpoint += f"/{section}"

        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        logging.info(f"Fetching OTX data for IOC: {ioc}, Type: {ioc_type}")
        response = requests.get(endpoint, headers=headers, timeout=15)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logging.error(f"Failed to fetch OTX data for {ioc} ({ioc_type}): {e}")
        return {}

def fetch_otx_data_threaded(iocs: list, ioc_type: str, section: str = '') -> list:
    results = []

    def fetch_single(ioc):
        return fetch_otx_data(ioc, ioc_type, section)

    with ThreadPoolExecutor(max_workers=5) as executor:  # Adjust max_workers based on API rate limits
        futures = {executor.submit(fetch_single, ioc): ioc for ioc in iocs}

        for future in as_completed(futures):
            try:
                result = future.result()
                logging.info(f"Enriched data fetched for IOC: {futures[future]}")
                results.append(result)
            except Exception as e:
                logging.error(f"Error in threaded fetching: {e}")

    return results

def enrich_with_ner_and_scoring(text: str) -> dict:
    logging.info("Starting IOC extraction and enrichment process.")
    iocs = extract_ner(text)
    logging.info(f"Extracted IOCs: {iocs}")
    enriched_iocs = []

    ioc_types_mapping = {
        "ipv4s": "IPv4",
        "ipv6s": "IPv6",
        "hashes": "file",
        "domains": "domain",
        "hostnames": "hostname",
        "urls": "url",
    }

    for ioc_type, otx_type in ioc_types_mapping.items():
        ioc_list = iocs.get(ioc_type, [])
        if not ioc_list:
            logging.info(f"No IOCs of type {ioc_type} to process.")
            continue

        logging.info(f"Processing {len(ioc_list)} IOCs of type {ioc_type}.")
        otx_data_list = fetch_otx_data_threaded(ioc_list, otx_type)

        for ioc, otx_data in zip(ioc_list, otx_data_list):
            risk_score = calculate_risk_score(otx_data)
            enriched_iocs.append({"ioc": ioc, "type": ioc_type, "risk_score": risk_score})
            logging.info(f"Enriched IOC: {ioc}, Type: {ioc_type}, Risk Score: {risk_score}")

    return {"entities": iocs, "enriched_iocs": enriched_iocs}

def extract_ner(text: str) -> dict:
    """
    Extract Named Entities and other IOCs from the given text.

    Args:
        text (str): Input text containing potential IOCs.

    Returns:
        dict: Dictionary containing extracted IOCs categorized by type.
    """
    if nlp is None:
        logging.warning("SpaCy NLP model is not loaded. Returning empty IOC result.")
        return {
            "actors": [],
            "malware": [],
            "mitre_techniques": [],
            "cves": [],
            "tools": [],
            "campaigns": [],
            "ipv4s": [],
            "ipv6s": [],
            "domains": [],
            "urls": []
        }

    # Normalize text to handle defanged IOCs
    def normalize_text(input_text):
        return input_text.replace("[.]", ".").replace("(.)", ".").replace("hxxp", "http")

    text = normalize_text(text)

    # Ensure MITRE cache is loaded
    if not MITRE_CACHE["techniques"]:
        logging.info("MITRE cache is empty. Fetching MITRE data.")
        fetch_mitre_data()

    # Process text with SpaCy NLP
    doc = nlp(text)

    # Extract various IOC patterns using IOC_PATTERNS
    extracted_iocs = {
        key: pattern.findall(text) for key, pattern in IOC_PATTERNS.items()
    }

    # Log extracted entities
    for key, values in extracted_iocs.items():
        logging.info(f"Extracted {key.capitalize()}: {sorted(set(values))}")

    return extracted_iocs