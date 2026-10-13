from __future__ import annotations

import json
from pathlib import Path
from app.utils.hashing import sha256_file


def build_manifest(root: Path, files: list[Path], output: Path) -> dict[str, object]:
    root = root.resolve()
    entries = {p.resolve().relative_to(root).as_posix(): sha256_file(p) for p in files}
    manifest: dict[str, object] = {"version": 1, "files": dict(sorted(entries.items()))}
    output.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return manifest


def verify_manifest(root: Path, manifest_path: Path) -> bool:
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        return all((root / relative).is_file() and sha256_file(root / relative) == digest
                   for relative, digest in data["files"].items())
    except (OSError, ValueError, KeyError, TypeError):
        return False
