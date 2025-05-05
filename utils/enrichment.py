import requests
import re
import spacy

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
nlp = spacy.load("en_core_web_sm")

# Cache dictionary to avoid repeated downloads
MITRE_CACHE = {
    "techniques": set(),
    "actors": set(),
    "malwares": set(),
}

def fetch_mitre_data():
    try:
        response = requests.get(MITRE_URL, timeout=15)
        response.raise_for_status()
        data = response.json()

        for obj in data.get("objects", []):
            if obj.get("type") == "attack-pattern":
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack" and "external_id" in ref:
                        MITRE_CACHE["techniques"].add(ref["external_id"])
            elif obj.get("type") == "intrusion-set":
                MITRE_CACHE["actors"].add(obj.get("name", ""))
                for alias in obj.get("aliases", []):
                    MITRE_CACHE["actors"].add(alias)
            elif obj.get("type") == "malware":
                MITRE_CACHE["malwares"].add(obj.get("name", ""))
                for alias in obj.get("aliases", []):
                    MITRE_CACHE["malwares"].add(alias)
    except Exception as e:
        print(f"[!] Failed to fetch MITRE data: {e}")

def extract_ner(text):
    if not MITRE_CACHE["techniques"]:
        fetch_mitre_data()

    doc = nlp(text)
    actors = set()
    malwares = set()
    techniques = set()
    cves = set(re.findall(r"CVE-\d{4}-\d{4,7}", text))

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

def enrich_with_ner(text):
    return extract_ner(text)
