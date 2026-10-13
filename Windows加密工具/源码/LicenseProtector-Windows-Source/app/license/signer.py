from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from .schema import LicenseDocument, LicensePayload, canonical_json


class LicenseSigner:
    @staticmethod
    def generate_keypair(private_path: Path, public_path: Path) -> None:
        private = Ed25519PrivateKey.generate()
        private_path.parent.mkdir(parents=True, exist_ok=True)
        private_path.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        public_path.write_bytes(private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

    @staticmethod
    def load_private(path: Path) -> Ed25519PrivateKey:
        return serialization.load_pem_private_key(path.read_bytes(), password=None)

    @staticmethod
    def load_public(path: Path) -> Ed25519PublicKey:
        return serialization.load_pem_public_key(path.read_bytes())

    @staticmethod
    def keys_match(private_key: Ed25519PrivateKey, public_key: Ed25519PublicKey) -> bool:
        """Confirm a build uses the public half of its signing key."""
        return private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ) == public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    @staticmethod
    def sign_bytes(value: bytes, private_key: Ed25519PrivateKey) -> str:
        return base64.b64encode(private_key.sign(value)).decode("ascii")

    @staticmethod
    def verify_bytes(value: bytes, signature: str, public_key: Ed25519PublicKey) -> bool:
        try:
            public_key.verify(base64.b64decode(signature, validate=True), value)
            return True
        except Exception:
            return False

    @classmethod
    def sign(cls, payload: LicensePayload, private_key: Ed25519PrivateKey) -> LicenseDocument:
        return LicenseDocument(payload, cls.sign_bytes(canonical_json(payload.to_dict()), private_key))

    @classmethod
    def verify(cls, document: LicenseDocument, public_key: Ed25519PublicKey) -> bool:
        return cls.verify_bytes(canonical_json(document.payload.to_dict()), document.signature, public_key)

    @staticmethod
    def write(document: LicenseDocument, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document.to_dict(), ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    @staticmethod
    def read(path: Path) -> LicenseDocument:
        try:
            return LicenseDocument.from_dict(json.loads(path.read_text(encoding="utf-8")))
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError("LIC-1006 License malformed") from exc
