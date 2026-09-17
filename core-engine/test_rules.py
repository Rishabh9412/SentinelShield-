from detector import inspect_input

tests = [
    "hello world",
    "' OR '1'='1",
    "<script>alert(1)</script>",
    "../../etc/passwd",
    "ls; whoami",
]

for t in tests:
    result = inspect_input(t)
    print(f"{t!r} -> {result}")