import ipaddress

def normalize_ipv4(value: str) -> str:
    try:
        address = ipaddress.ip_address((value or "").strip())
        if address.version != 4:
            return ""
        return str(address)
    except ValueError:
        return ""

def ipv4_matches(current: list[str] | str, licensed: str | None) -> bool:
    expected = normalize_ipv4(licensed or "")
    values = [current] if isinstance(current, str) else current
    return bool(expected) and any(normalize_ipv4(item) == expected for item in values)
