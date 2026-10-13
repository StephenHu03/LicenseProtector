from pathlib import Path

def detect_framework(root: Path) -> str:
    if (root / "artisan").exists() and (root / "bootstrap" / "app.php").exists():
        return "Laravel"
    if (root / "think").exists() or (root / "thinkphp").is_dir():
        return "ThinkPHP"
    if (root / "bin" / "console").exists() and (root / "config" / "bundles.php").exists():
        return "Symfony"
    composer = root / "composer.json"
    if composer.is_file() and "hyperf" in composer.read_text(encoding="utf-8", errors="ignore").lower():
        return "Hyperf"
    return "Native PHP"
