from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from .framework_detector import detect_framework
from .entry_detector import detect_entry


@dataclass(frozen=True)
class ProjectInfo:
    root: Path
    php_files: tuple[Path, ...]
    framework: str
    entry: Path


class ProjectScanner:
    def scan(self, root: Path, entry: Path | None = None) -> ProjectInfo:
        root = root.expanduser().resolve()
        if not root.is_dir():
            raise FileNotFoundError(f"Project directory does not exist: {root}")
        php_files = tuple(sorted(p for p in root.rglob("*.php") if ".git" not in p.parts))
        if not php_files:
            raise ValueError("No PHP files found in project")
        selected = (root / entry).resolve() if entry and not entry.is_absolute() else (entry.resolve() if entry else detect_entry(root))
        if not selected or not selected.is_file() or root not in selected.parents:
            raise ValueError("Unable to determine a safe PHP entry file")
        return ProjectInfo(root, php_files, detect_framework(root), selected)
