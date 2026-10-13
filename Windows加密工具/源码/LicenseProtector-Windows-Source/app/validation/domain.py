from urllib.parse import urlsplit

def normalize_domain(value: str) -> str:
    value = (value or "").strip().lower()
    if "://" in value:
        value = urlsplit(value).hostname or ""
    else:
        value = value.split("/", 1)[0].split(":", 1)[0]
    return value.rstrip(".")

def domain_matches(current: str, licensed: str | None) -> bool:
    return bool(licensed) and normalize_domain(current) == normalize_domain(licensed)
