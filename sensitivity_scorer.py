import json
import re
import os
import sys
import csv

WEIGHTS_PATH = os.path.join(os.path.dirname(__file__), "weights.json")
with open(WEIGHTS_PATH, "r") as f:
    CONFIG = json.load(f)

DIRECT = CONFIG["direct_identifiers"]
QUASI = CONFIG["quasi_identifiers"]
NON = CONFIG["non_sensitive"]
COMBO = CONFIG["combinations"]

PATTERNS = {
    "ip": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ),
    "username": re.compile(
        r'(?:'
        r'for\s+(?:invalid\s+user\s+)?(\w+)\s+from'
        r'|invalid\s+user\s+(\w+)'
        r'|user=(\w+)'
        r'|ruser=(\w+)'
        r'|logname=(\w+)'
        r'|username[=:\s]+(\S+)'
        r')',
        re.IGNORECASE
    ),
    "hostname": re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){2,}[a-zA-Z]{2,}\b'
    ),
    "file_path": re.compile(
        r'/(?:[a-zA-Z0-9_\-\.]+/){1,}[a-zA-Z0-9_\-\.]*'
    ),
    "url": re.compile(
        r'https?://[^\s\'">\]]+'
    ),
    "port": re.compile(
        r'(?:port[=:\s]+\d{1,5}|\bdport[=:\s]+\d{1,5}|\bsport[=:\s]+\d{1,5})',
        re.IGNORECASE
    ),
    "protocol": re.compile(
        r'\b(?:HTTP/[12](?:\.\d)?|HTTPS|FTP|SMTP|SSH2?|DNS|TCP|UDP|SSL|TLS)\b',
        re.IGNORECASE
    ),
}

def detect_values(row: dict) -> dict:
    detected = {}

    if any(row.get(f, "").strip() for f in ["Time", "Date", "Month", "Day"]):
        detected["timestamp"] = True

    if row.get("Level", "").strip():
        detected["log_level"] = True

    pid = row.get("Pid", row.get("PID", "")).strip()
    if pid and pid.isdigit():
        detected["process_id"] = True

    component = row.get("Component", "").strip()
    if component and "." in component:
        detected["component"] = True

    content = row.get("Content", "").strip()
    if content:
        for field, pattern in PATTERNS.items():
            if pattern.search(content):
                detected[field] = True

        if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}\b', content):
            detected["port"] = True

    return detected

def classify(score: float) -> str:
    if score >= 2.0: return "CRITICAL"
    elif score >= 1.0: return "HIGH"
    elif score >= 0.5: return "MEDIUM"
    return "LOW"

def apply_weights(detected: dict) -> dict:
    score = 0
    reasons = []
    direct_present = []
    quasi_present = []
 
    for field, weight in DIRECT.items():
        if field in detected:
            score += weight
            direct_present.append(field)
            reasons.append(f"{field}_direct")
 
    for field, weight in QUASI.items():
        if field in detected:
            score += weight
            quasi_present.append(field)
            reasons.append(f"{field}_quasi")
 
    for field, weight in NON.items():
        if field in detected:
            score += weight
            reasons.append(f"{field}_non")
 
    q_count = len(quasi_present)
    d_count = len(direct_present)
 
    # Combination amplifier within tier only
    # Quasi: amplifier for 2+ quasi-identifiers
    if q_count >= 2:
        bonus = COMBO["combination_multiplier"] * (q_count - 1)
        score += bonus
        reasons.append(f"quasi_combination_{q_count}")
 
    # Direct: amplifier for 2+ direct identifiers
    if d_count >= 2:
        bonus = COMBO["combination_multiplier"] * (d_count - 1)
        score += bonus
        reasons.append(f"direct_combination_{d_count}")
 
    return {
        "score": round(score, 2),
        "level": classify(score),
        "direct_identifiers": direct_present,
        "quasi_identifiers": quasi_present,
        "reasons": reasons,
    }

def process_logs(file_path: str) -> list:
    results = []
    with open(file_path, "r", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            parts = [
                row.get(field, "").strip()
                for field in ["Date", "Month", "Day", "Time"]
                if row.get(field, "").strip()
            ]
            for field in ["Level", "Component"]:
                v = row.get(field, "").strip()
                if v:
                    parts.append(v)
            pid = row.get("Pid", row.get("PID", "")).strip()
            if pid:
                parts.append(f"[{pid}]")
            content = row.get("Content", "").strip()
            if content:
                parts.append(content)

            results.append({
                "log":      " ".join(parts),
                "analysis": apply_weights(detect_values(row))
            })

    return results