from __future__ import annotations

from pathlib import Path
import os

MARKER = "// LICENSE_PROTECTOR_BOOTSTRAP_V1"


class BootstrapInjector:
    def inject(self, project_root: Path, entry: Path) -> None:
        entry = entry.resolve()
        project_root = project_root.resolve()
        if project_root not in entry.parents:
            raise ValueError("Entry must be inside project root")
        text = entry.read_text(encoding="utf-8")
        if MARKER in text:
            return
        watchdog = project_root / "protected" / "watchdog" / "loader.php"
        # ``relative_to`` only handles descendants; an entry such as
        # ``public/index.php`` must walk up one directory first.
        relative = os.path.relpath(watchdog, entry.parent).replace(os.sep, "/")
        line = f"{MARKER}\nrequire_once __DIR__ . '/{relative}';\n"
        # Keep a shebang/open tag and prepend before application code.
        if text.startswith("<?php"):
            text = "<?php\n" + line + text[len("<?php"):]
        else:
            text = "<?php\n" + line + "?>\n" + text
        entry.write_text(text, encoding="utf-8", newline="\n")
