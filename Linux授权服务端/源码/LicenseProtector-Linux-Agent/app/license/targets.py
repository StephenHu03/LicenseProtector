"""Normalization and validation for the allow-listed license targets."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from app.validation.domain import normalize_domain
from app.validation.ipv4 import normalize_ipv4


def _values(value: str | Iterable[str] | None) -> list[str]:
    """Accept GUI multi-line input and repeated CLI arguments in one place."""
    if value is None:
        return []
    parts = [value] if isinstance(value, str) else value
    return [item.strip() for part in parts for item in re.split(r"[,;\r\n]+", str(part)) if item.strip()]


def _unique(values: Iterable[str]) -> tuple[str, ...]:
    """Keep input order while preventing duplicate signed targets."""
    return tuple(dict.fromkeys(values))


def normalize_domains(value: str | Iterable[str] | None) -> tuple[str, ...]:
    """Normalize a comma/newline-separated collection of exact host names."""
    normalized: list[str] = []
    for raw in _values(value):
        domain = normalize_domain(raw)
        if not domain:
            raise ValueError(f"Invalid domain: {raw}")
        normalized.append(domain)
    return _unique(normalized)


def normalize_ipv4s(value: str | Iterable[str] | None) -> tuple[str, ...]:
    """Normalize a comma/newline-separated collection of IPv4 addresses."""
    normalized: list[str] = []
    for raw in _values(value):
        address = normalize_ipv4(raw)
        if not address:
            raise ValueError(f"Invalid IPv4 address: {raw}")
        normalized.append(address)
    return _unique(normalized)


@dataclass(frozen=True)
class LicenseTargets:
    """The exact hosts and server addresses allowed by one License."""

    domains: tuple[str, ...] = ()
    ipv4s: tuple[str, ...] = ()

    @classmethod
    def create(cls, domains: str | Iterable[str] | None, ipv4s: str | Iterable[str] | None) -> "LicenseTargets":
        targets = cls(normalize_domains(domains), normalize_ipv4s(ipv4s))
        if not targets.domains and not targets.ipv4s:
            raise ValueError("At least one authorized domain or IPv4 address is required")
        return targets
