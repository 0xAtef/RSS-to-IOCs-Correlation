def calculate_risk_score(otx_data: dict) -> int:
    """
    Calculate a robust risk score for an IOC based on OTX data.

    Args:
        otx_data (dict): The data returned from the OTX API for an IOC.

    Returns:
        int: A risk score between 0 and 100.
    """
    # Validate required keys in OTX data
    if not isinstance(otx_data, dict):
        raise ValueError("Invalid otx_data format. Expected a dictionary.")

    # Default risk score
    risk_score = 0

    # Scoring caps (externalized for flexibility)
    scoring_caps = {
        "pulse_count_cap": 30,
        "reputation_cap": 20,
        "malicious_tag_score": 20,
        "ransomware_tag_score": 15,
        "phishing_tag_score": 10,
    }

    # 1. Check if pulse info exists
    pulse_info = otx_data.get("pulse_info", {})
    if pulse_info:
        # a- Add points based on the number of pulses
        pulse_count = pulse_info.get("count", 0)
        risk_score += min(pulse_count * 5, scoring_caps["pulse_count_cap"])

        # b- Add points for specific tags (e.g., malicious activity)
        tags = pulse_info.get("tags", [])
        if "malicious" in tags:
            risk_score += scoring_caps["malicious_tag_score"]
        if "ransomware" in tags:
            risk_score += scoring_caps["ransomware_tag_score"]
        if "phishing" in tags:
            risk_score += scoring_caps["phishing_tag_score"]

    # 2. Add points based on reputation score
    reputation = otx_data.get("reputation", 0)
    if reputation > 0:  # Only consider positive reputation scores
        risk_score += min(reputation // 2, scoring_caps["reputation_cap"])

    # 3. Check for threat indicators
    indicators = otx_data.get("indicators", [])
    if indicators:
        risk_score += 10  # Add 10 points if any indicators are present

    # 4. Adjust for other potential high-risk attributes
    if otx_data.get("is_known_malicious", False):
        risk_score += 20  # IOC is flagged as known malicious

    # Ensure the score is capped at 100
    return min(risk_score, 100)