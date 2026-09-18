import json
import os
from datetime import datetime
from zoneinfo import ZoneInfo

LOG_FILE = os.path.join(os.path.dirname(__file__), "sentinel_log.jsonl")


def log_event(ip, path, verdict, category=None):
    entry = {
        "timestamp": datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "path": path,
        "verdict": verdict,
        "category": category,
    }

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")