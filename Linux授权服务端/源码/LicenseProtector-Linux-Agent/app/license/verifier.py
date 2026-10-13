from __future__ import annotations

from datetime import datetime, timezone
from .schema import LicenseDocument
from .signer import LicenseSigner
from app.validation.domain import domain_matches
from app.validation.ipv4 import ipv4_matches

ERRORS = {
    "missing": "LIC-1001", "signature": "LIC-1002", "domain": "LIC-1003", "ipv4": "LIC-1004",
    "expired": "LIC-1005", "malformed": "LIC-1006", "environment": "LIC-1007", "integrity": "LIC-1008",
    "watchdog": "LIC-1009", "bootstrap": "LIC-1010",
}


class LicenseValidationError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code} {message}")
        self.code = code


def validate_document(document: LicenseDocument, public_key, current_domain: str, current_ips: list[str]) -> None:
    if not LicenseSigner.verify(document, public_key):
        raise LicenseValidationError(ERRORS["signature"], "License signature invalid")
    payload = document.payload
    if payload.bind_mode != "DOMAIN_OR_IPV4":
        raise LicenseValidationError(ERRORS["malformed"], "Unsupported bind mode")
    if payload.expires_at:
        try:
            expiry = datetime.fromisoformat(payload.expires_at.replace("Z", "+00:00"))
            if expiry <= datetime.now(timezone.utc):
                raise LicenseValidationError(ERRORS["expired"], "License expired")
        except ValueError as exc:
            raise LicenseValidationError(ERRORS["malformed"], "Invalid expiry") from exc
    domain_ok = any(domain_matches(current_domain, domain) for domain in payload.domains)
    ip_ok = any(ipv4_matches(current_ips, ipv4) for ipv4 in payload.ipv4s)
    if not domain_ok and not ip_ok:
        if payload.ipv4s and not current_ips:
            raise LicenseValidationError(ERRORS["environment"], "Environment IP unresolved")
        raise LicenseValidationError(ERRORS["domain"], "Domain and IPv4 mismatch")
