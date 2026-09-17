import json
import os
import time

TRACKER_FILE = os.path.join(os.path.dirname(__file__), "ip_tracker.json")

FLAG_THRESHOLD = 3
BAN_THRESHOLD = 10


def _load():
    if not os.path.exists(TRACKER_FILE):
        return {}
    with open(TRACKER_FILE, "r") as f:
        return json.load(f)


def _save(data):
    with open(TRACKER_FILE, "w") as f:
        json.dump(data, f, indent=2)


def record_violation(ip, category):
    data = _load()

    if ip not in data:
        data[ip] = {
            "violation_count": 0,
            "categories": [],
            "first_seen": time.strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen": None,
            "status": "clean",
        }

    data[ip]["violation_count"] += 1
    data[ip]["categories"].append(category)
    data[ip]["last_seen"] = time.strftime("%Y-%m-%d %H:%M:%S")

    if data[ip]["violation_count"] >= BAN_THRESHOLD:
        data[ip]["status"] = "banned"
    elif data[ip]["violation_count"] >= FLAG_THRESHOLD:
        data[ip]["status"] = "flagged"

    _save(data)
    return data[ip]["status"]


def is_banned(ip):
    data = _load()
    return data.get(ip, {}).get("status") == "banned"


def get_all_flagged():
    data = _load()
    return {ip: info for ip, info in data.items() if info["status"] in ("flagged", "banned")}