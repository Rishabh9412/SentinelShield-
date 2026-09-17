from limiter import check_rate_limit

test_ip = "192.168.1.50"

for i in range(20):
    blocked = check_rate_limit(test_ip)
    print(f"Request {i + 1}: {'BLOCKED' if blocked else 'allowed'}")