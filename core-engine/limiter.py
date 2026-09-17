import time

REQUEST_WINDOW = 10
REQUEST_THRESHOLD = 15

ip_request_log = {}


def check_rate_limit(ip):
    now = time.time()

    if ip not in ip_request_log:
        ip_request_log[ip] = []

    ip_request_log[ip] = [t for t in ip_request_log[ip] if now - t < REQUEST_WINDOW]

    ip_request_log[ip].append(now)

    if len(ip_request_log[ip]) > REQUEST_THRESHOLD:
        return True

    return False