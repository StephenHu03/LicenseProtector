from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from typing import Any, Iterable

from app.license.targets import LicenseTargets
from app.runtime.profile import PHP_HYPERF


def canonical_json(value: dict[str, Any]) -> bytes:
    """Serialize payloads exactly as the PHP verifier expects them."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class LicensePayload:
    """Signed, versioned authorization targets and runtime metadata."""

    version: int
    license_id: str
    product_id: str
    product_version: str
    bind_mode: str
    domains: tuple[str, ...]
    ipv4s: tuple[str, ...]
    language: str
    framework: str
    php_min_version: str
    issued_at: str
    expires_at: str | None = None
    features: tuple[str, ...] = field(default_factory=tuple)

    @property
    def domain(self) -> str | None:
        """Compatibility accessor for integrations that used one domain."""
        return self.domains[0] if self.domains else None

    @property
    def ipv4(self) -> str | None:
        """Compatibility accessor for integrations that used one IPv4 address."""
        return self.ipv4s[0] if self.ipv4s else None

    @classmethod
    def create(
        cls,
        license_id: str,
        product_version: str,
        domains: str | Iterable[str] | None,
        ipv4s: str | Iterable[str] | None,
        product_id: str = "PRODUCT-001",
        expires_at: str | None = None,
        features: list[str] | None = None,
        php_min_version: str = "8.1",
    ) -> "LicensePayload":
        targets = LicenseTargets.create(domains, ipv4s)
        return cls(
            2,
            license_id,
            product_id,
            product_version,
            "DOMAIN_OR_IPV4",
            targets.domains,
            targets.ipv4s,
            PHP_HYPERF.language,
            PHP_HYPERF.framework,
            PHP_HYPERF.normalize_php_min_version(php_min_version),
            datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            expires_at,
            tuple(features or []),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "license_id": self.license_id,
            "product_id": self.product_id,
            "product_version": self.product_version,
            "bind_mode": self.bind_mode,
            "domains": list(self.domains),
            "ipv4s": list(self.ipv4s),
            "language": self.language,
            "framework": self.framework,
            "php_min_version": self.php_min_version,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "features": list(self.features),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LicensePayload":
        required = ["version", "license_id", "product_id", "product_version", "bind_mode", "issued_at"]
        if any(key not in data for key in required):
            raise ValueError("LIC-1006 License malformed")
        # Version 1 packages contained scalar domain/ipv4 fields. Keeping this
        # reader compatible lets vendor-side tooling inspect old deliveries.
        domains = data.get("domains", [data["domain"]] if data.get("domain") else [])
        ipv4s = data.get("ipv4s", [data["ipv4"]] if data.get("ipv4") else [])
        targets = LicenseTargets.create(domains, ipv4s)
        return cls(
            int(data["version"]),
            str(data["license_id"]),
            str(data["product_id"]),
            str(data["product_version"]),
            str(data["bind_mode"]),
            targets.domains,
            targets.ipv4s,
            str(data.get("language", "PHP")),
            str(data.get("framework", "Hyperf")),
            PHP_HYPERF.normalize_php_min_version(str(data.get("php_min_version", "8.0"))),
            str(data["issued_at"]),
            data.get("expires_at"),
            tuple(data.get("features", [])),
        )


@dataclass(frozen=True)
class LicenseDocument:
    payload: LicensePayload
    signature: str

    def to_dict(self) -> dict[str, Any]:
        result = self.payload.to_dict()
        result["signature"] = self.signature
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LicenseDocument":
        signature = data.get("signature")
        if not isinstance(signature, str) or not signature:
            raise ValueError("LIC-1006 License malformed")
        return cls(LicensePayload.from_dict(data), signature)
