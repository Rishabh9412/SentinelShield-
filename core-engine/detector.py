import re

SQLI_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
    r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
    r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
    r"(union)(.*)(select)",
    r"(select)(.*)(from)",
    r"(drop\s+table)",
    r"(insert\s+into)",
]

XSS_PATTERNS = [
    r"<script.*?>.*?</script.*?>",
    r"<.*?javascript:.*?>",
    r"on\w+\s*=\s*[\"\'].*?[\"\']",
    r"<img.*?onerror.*?>",
    r"<iframe.*?>",
    r"alert\s*\(",
]

LFI_PATTERNS = [
    r"(\.\./)|(\.\.\\)",
    r"(\%2e\%2e\%2f)",
    r"(etc/passwd)",
    r"(boot\.ini)",
    r"(win\.ini)",
]

TRAVERSAL_PATTERNS = [
    r"(\.\.(\/|\\)){2,}",
    r"(\%2e\%2e(\%2f|\%5c)){2,}",
]

CMD_INJECTION_PATTERNS = [
    r"(;|\||&&)\s*(ls|cat|whoami|pwd|dir|net\s+user|ping|curl|wget)",
    r"(\$\(.*\))",
    r"(`.*`)",
]

RULE_CATEGORIES = {
    "SQL Injection": SQLI_PATTERNS,
    "XSS": XSS_PATTERNS,
    "LFI": LFI_PATTERNS,
    "Directory Traversal": TRAVERSAL_PATTERNS,
    "Command Injection": CMD_INJECTION_PATTERNS,
}


def inspect_input(value):
    if not value:
        return None

    for category, patterns in RULE_CATEGORIES.items():
        for pattern in patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return category

    return None
