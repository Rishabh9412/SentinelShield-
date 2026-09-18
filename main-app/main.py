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


@app.route("/demo")
def demo():
    return """
    <html>
    <head><title>SentinelShield Demo</title>
    <style>
      body { font-family: monospace; max-width: 500px; margin: 40px auto; }
      fieldset { margin-bottom: 20px; padding: 15px; }
      input { width: 100%; padding: 6px; margin: 6px 0; }
      button { padding: 6px 14px; }
    </style>
    </head>
    <body>
      <h2>SentinelShield — Try It Yourself</h2>

      <fieldset>
        <legend>Search (try: laptop, or &lt;script&gt;alert(1)&lt;/script&gt;)</legend>
        <form action="/search" method="get">
          <input type="text" name="q" placeholder="Search query">
          <button type="submit">Search</button>
        </form>
      </fieldset>

      <fieldset>
        <legend>Login (try: admin' OR '1'='1)</legend>
        <form action="/login" method="post">
          <input type="text" name="username" placeholder="Username">
          <input type="password" name="password" placeholder="Password">
          <button type="submit">Login</button>
        </form>
      </fieldset>

      <fieldset>
        <legend>File lookup (try: readme.txt, or ../../etc/passwd)</legend>
        <form action="/file" method="get">
          <input type="text" name="name" placeholder="Filename">
          <button type="submit">Open File</button>
        </form>
      </fieldset>
    </body>
    </html>
    """


if __name__ == "__main__":
    app.run(debug=True, port=5000)