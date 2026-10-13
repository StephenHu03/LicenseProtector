from pathlib import Path

# Common HTTP front controllers plus Hyperf's executable bootstrap. Projects
# without one of these are rejected so an unknown file is never modified.
_CANDIDATES = ("public/index.php", "index.php", "web/index.php", "bin/hyperf.php")

def detect_entry(root: Path) -> Path | None:
    for relative in _CANDIDATES:
        candidate = root / relative
        if candidate.is_file():
            return candidate.resolve()
    return None
