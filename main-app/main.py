import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "core-engine"))

import json
from flask import Flask, request, abort, jsonify
from flask_cors import CORS
from detector import inspect_input
from limiter import check_rate_limit
from logger import log_event, LOG_FILE
from ip_tracker import record_violation, is_banned, get_all_flagged

app = Flask(__name__)
CORS(app)


@app.before_request
def waf_check():
    if request.path.startswith("/api/"):
        return

    ip = request.remote_addr
    path = request.path

    if is_banned(ip):
        log_event(ip, path, "blocked", "Banned IP")
        abort(403)

    if check_rate_limit(ip):
        log_event(ip, path, "blocked", "Rate Limit Exceeded")
        record_violation(ip, "Rate Limit Exceeded")
        abort(429)

    values_to_check = list(request.args.values()) + list(request.form.values())

    for value in values_to_check:
        category = inspect_input(value)
        if category:
            log_event(ip, path, "blocked", category)
            record_violation(ip, category)
            abort(403)

    log_event(ip, path, "allowed")


@app.route("/")
def home():
    return "Welcome to the Test App"


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    return f"Login attempt with username: {username}"


@app.route("/search")
def search():
    query = request.args.get("q")
    return f"Search results for: {query}"


@app.route("/file")
def file():
    filename = request.args.get("name")
    return f"Requested file: {filename}"


@app.route("/api/logs")
def get_logs():
    logs = []

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            for line in f:
                logs.append(json.loads(line))

    return jsonify(logs)


@app.route("/api/flagged")
def get_flagged():
    return jsonify(get_all_flagged())


if __name__ == "__main__":
    app.run(debug=True, port=5000)