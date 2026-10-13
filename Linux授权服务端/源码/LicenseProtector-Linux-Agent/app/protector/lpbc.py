"""Versioned LicenseProtector bytecode container (LPBC v1).

The container is intentionally independent from Zend opcodes. A future native
PHP Loader can decrypt and execute the payload without needing a PHP-version-
specific opcode dump. This module only defines the authenticated container;
it does not claim to be a PHP execution engine.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import struct
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app.license.signer import LicenseSigner


MAGIC = b"LPBC\x01"
NONCE_SIZE = 12
KEY_SIZE = 32
SIGNATURE_SIZE = 64
MAX_HEADER_SIZE = 64 * 1024


class LPBCError(ValueError):
    """Raised when an LPBC container is malformed or fails authentication."""


@dataclass(frozen=True)
class LPBCHeader:
    path: str
    payload_sha256: str
    payload_type: str = "php-source-v1"
    algorithm: str = "AES-256-GCM"
    format_version: int = 1

    @property
    def source_sha256(self) -> str:
        """Compatibility alias for pre-LPBC-v1 callers."""
        return self.payload_sha256

    def to_dict(self) -> dict[str, object]:
        return {
            "algorithm": self.algorithm,
            "format_version": self.format_version,
            "path": self.path,
            "payload_type": self.payload_type,
            "payload_sha256": self.payload_sha256,
        }


@dataclass(frozen=True)
class LPBCContainer:
    header: LPBCHeader
    nonce: bytes
    ciphertext: bytes
    signature: bytes


def _canonical_json(value: dict[str, object]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _validate_key(key: bytes) -> bytes:
    if len(key) != KEY_SIZE:
        raise LPBCError("LPBC runtime key must be exactly 32 bytes")
    return key


def derive_file_key(runtime_key: bytes, relative_path: str) -> bytes:
    """Derive a separate AEAD key for each protected path."""
    key = _validate_key(runtime_key)
    path = _validate_path(relative_path).encode("utf-8")
    return hmac.new(key, b"LPBC-FILE-KEY\x00" + path, hashlib.sha256).digest()


def _validate_path(relative_path: str) -> str:
    path = Path(relative_path)
    if not relative_path or path.is_absolute() or ".." in path.parts or "\\" in relative_path:
        raise LPBCError(f"Invalid LPBC relative path: {relative_path!r}")
    normalized = path.as_posix()
    if not re.fullmatch(r"[A-Za-z0-9_./-]+", normalized):
        raise LPBCError(f"LPBC path contains unsupported characters: {relative_path!r}")
    return normalized


def generate_runtime_key(path: Path) -> bytes:
    """Create the runtime key provisioned to the Linux Agent."""
    key = os.urandom(KEY_SIZE)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as key_file:
        key_file.write(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


def create_runtime_key(path: Path) -> bytes:
    """Create an Agent key explicitly, refusing to overwrite an existing key."""
    if path.exists():
        raise FileExistsError(f"Runtime key already exists: {path}")
    return generate_runtime_key(path)


def load_runtime_key(path: Path) -> bytes:
    return _validate_key(path.read_bytes())


def encode_source(
    source: bytes,
    relative_path: str,
    runtime_key: bytes,
    signing_key: Ed25519PrivateKey,
    payload_type: str = "php-source-v1",
) -> bytes:
    """Encode one source payload into a signed LPBC container."""
    key = derive_file_key(runtime_key, relative_path)
    if payload_type not in {"php-source-v1", "ir-v1"}:
        raise LPBCError(f"Unsupported LPBC payload type: {payload_type}")
    header = LPBCHeader(_validate_path(relative_path), hashlib.sha256(source).hexdigest(), payload_type=payload_type)
    header_bytes = _canonical_json(header.to_dict())
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, source, header_bytes)
    signed = MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes + nonce + ciphertext
    signature = base64.b64decode(LicenseSigner.sign_bytes(signed, signing_key), validate=True)
    return signed + signature


def decode_container(data: bytes, runtime_key: bytes, public_key: Ed25519PublicKey) -> tuple[LPBCHeader, bytes]:
    """Verify and decrypt an LPBC payload for Loader and protocol tests."""
    key = _validate_key(runtime_key)
    minimum = len(MAGIC) + 4 + NONCE_SIZE + 16 + SIGNATURE_SIZE
    if len(data) < minimum or not data.startswith(MAGIC):
        raise LPBCError("Invalid LPBC header")
    header_size = struct.unpack(">I", data[len(MAGIC):len(MAGIC) + 4])[0]
    header_start = len(MAGIC) + 4
    header_end = header_start + header_size
    if header_size == 0 or header_size > MAX_HEADER_SIZE or header_end + NONCE_SIZE + 16 + SIGNATURE_SIZE > len(data):
        raise LPBCError("Invalid LPBC header size")
    signed = data[:-SIGNATURE_SIZE]
    signature = data[-SIGNATURE_SIZE:]
    if not LicenseSigner.verify_bytes(signed, base64.b64encode(signature).decode("ascii"), public_key):
        raise LPBCError("LPBC signature invalid")
    try:
        raw_header = json.loads(data[header_start:header_end].decode("utf-8"))
        header = LPBCHeader(
            path=_validate_path(str(raw_header["path"])),
            payload_sha256=str(raw_header["payload_sha256"] if "payload_sha256" in raw_header else raw_header["source_sha256"]),
            payload_type=str(raw_header["payload_type"]),
            algorithm=str(raw_header["algorithm"]),
            format_version=int(raw_header["format_version"]),
        )
    except (KeyError, TypeError, ValueError, UnicodeDecodeError) as exc:
        raise LPBCError("Invalid LPBC metadata") from exc
    if header.algorithm != "AES-256-GCM" or header.format_version != 1 or header.payload_type not in {"php-source-v1", "ir-v1"}:
        raise LPBCError("Unsupported LPBC format")
    nonce_start = header_end
    nonce = data[nonce_start:nonce_start + NONCE_SIZE]
    ciphertext = data[nonce_start + NONCE_SIZE:-SIGNATURE_SIZE]
    try:
        key = derive_file_key(key, header.path)
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, data[header_start:header_end])
    except Exception as exc:
        raise LPBCError("LPBC payload authentication failed") from exc
    if hashlib.sha256(plaintext).hexdigest() != header.payload_sha256:
        raise LPBCError("LPBC payload digest mismatch")
    return header, plaintext


def encode_file(
    source_path: Path,
    project_root: Path,
    output_path: Path,
    runtime_key: bytes,
    signing_key: Ed25519PrivateKey,
    payload_type: str = "php-source-v1",
    payload: bytes | None = None,
) -> LPBCHeader:
    root = project_root.resolve()
    source = source_path.resolve()
    try:
        relative = source.relative_to(root).as_posix()
    except ValueError as exc:
        raise LPBCError(f"Source is outside project root: {source_path}") from exc
    source_data = source.read_bytes()
    data = source_data if payload is None else payload
    container = encode_source(data, relative, runtime_key, signing_key, payload_type=payload_type)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(container)
    return LPBCHeader(relative, hashlib.sha256(data).hexdigest(), payload_type=payload_type)
