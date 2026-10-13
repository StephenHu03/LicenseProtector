"""Signed metadata shared by the self-hosted Encoder, Agent, and Loader."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from app.license.signer import LicenseSigner


NATIVE_PROTOCOL = "LP-NATIVE-1"


def write_native_manifest(
    output_root: Path,
    artifacts: list[Path],
    project_root: Path,
    runtime_key_path: Path,
    private_key_path: Path,
    php_min_version: str = "8.1",
    platforms: tuple[str, ...] = ("linux-x86_64",),
    tracked_paths: Iterable[Path] = (),
    framework: str = "php",
) -> tuple[Path, Path]:
    """Write signed artifact metadata without copying the Agent key.

    Only the key fingerprint is published. The key itself stays on the Agent
    host and is never placed under ``output_root``.
    """
    key_path = runtime_key_path.resolve()
    if not key_path.is_file():
        raise FileNotFoundError(f"Agent runtime key not found: {key_path}")
    if framework not in {"php", "hyperf"}:
        raise ValueError(f"Unsupported native runtime framework: {framework}")
    import hashlib

    files: list[dict[str, Any]] = []
    for artifact in artifacts:
        artifact = artifact.resolve()
        relative = artifact.relative_to(output_root.resolve()).as_posix()
        files.append({"path": relative, "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()})
    for tracked in tracked_paths:
        tracked = tracked.resolve()
        relative = tracked.relative_to(output_root.resolve()).as_posix()
        if not tracked.is_file():
            raise FileNotFoundError(f"Native manifest file does not exist: {tracked}")
        files.append({"path": relative, "sha256": hashlib.sha256(tracked.read_bytes()).hexdigest()})
    if len({item["path"] for item in files}) != len(files):
        raise ValueError("Native manifest contains duplicate paths")
    payload: dict[str, Any] = {
        "protocol": NATIVE_PROTOCOL,
        "format": "LPBC",
        "format_version": 1,
        "framework": framework,
        "php_min_version": php_min_version,
        "platforms": list(platforms),
        "runtime_key_sha256": hashlib.sha256(key_path.read_bytes()).hexdigest(),
        "files": sorted(files, key=lambda item: item["path"]),
    }
    manifest = output_root / "protected" / "lpbc" / "manifest.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    signature = output_root / "protected" / "lpbc" / "manifest.sig"
    signing_key = LicenseSigner.load_private(private_key_path)
    signature.write_text(LicenseSigner.sign_bytes(manifest.read_bytes(), signing_key) + "\n", encoding="ascii")
    return manifest, signature
