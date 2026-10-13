"""Conservative, free PHP source hardening for selected delivery files.

This is intentionally not presented as encryption. It uses PHP's tokenizer so
comments and redundant whitespace are removed without touching identifiers or
reflection-sensitive names. Commercial encoders can be added later without
changing the selection and signed-manifest pipeline.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
import shutil
import subprocess


class SourceHardeningError(RuntimeError):
    """Raised when a selected source file cannot be safely transformed."""


# T_DOC_COMMENT is deliberately preserved because legacy Hyperf projects can
# use it for annotations. Every whitespace token is retained as one separator,
# avoiding token-merging changes such as turning `+ +` into `++`.
_PHP_HARDENER = r'''$source = stream_get_contents(STDIN);
if (!is_string($source)) { fwrite(STDERR, "Unable to read PHP source\n"); exit(2); }
$output = '';
foreach (token_get_all($source) as $token) {
    if (!is_array($token)) { $output .= $token; continue; }
    [$kind, $text] = $token;
    if ($kind === T_COMMENT) {
        $output .= str_contains($text, "\n") ? str_repeat("\n", substr_count($text, "\n")) : ' ';
        continue;
    }
    if ($kind === T_WHITESPACE) {
        $output .= str_contains($text, "\n") ? "\n" : ' ';
        continue;
    }
    $output .= $text;
}
fwrite(STDOUT, $output);'''


def normalize_source_paths(project_root: Path, selections: Iterable[Path]) -> tuple[Path, ...]:
    """Return ordered project-relative PHP files from user file/directory picks."""
    root = project_root.resolve()
    selected: list[Path] = []
    for raw in selections:
        candidate = raw if raw.is_absolute() else root / raw
        try:
            candidate = candidate.resolve()
            candidate.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"Selected source must be inside the project: {raw}") from exc
        if candidate.is_dir():
            files = sorted(path for path in candidate.rglob("*.php") if path.is_file())
        elif candidate.is_file() and candidate.suffix.lower() == ".php":
            files = [candidate]
        else:
            raise ValueError(f"Selected source must be a PHP file or directory: {raw}")
        selected.extend(file.relative_to(root) for file in files)
    return tuple(dict.fromkeys(selected))


def harden_php_sources(project_root: Path, selections: Iterable[Path], php_executable: str = "php") -> list[Path]:
    """Strip selected sources through PHP's tokenizer and lint before replacing.

    The caller provides paths relative to ``project_root``. All transformed
    copies are linted first, so a failed transformation leaves project files
    untouched.
    """
    root = project_root.resolve()
    files = normalize_source_paths(root, selections)
    if not files:
        return []
    executable = shutil.which(php_executable) or (php_executable if Path(php_executable).is_file() else None)
    if not executable:
        raise SourceHardeningError(
            f"PHP executable not found: {php_executable}. Install PHP or configure its executable path."
        )

    staging = root / ".license-protector-hardening"
    try:
        for relative in files:
            source = root / relative
            result = subprocess.run(
                [executable, "-r", _PHP_HARDENER],
                input=source.read_bytes(),
                capture_output=True,
                check=False,
            )
            if result.returncode != 0 or not result.stdout:
                detail = result.stderr.decode("utf-8", errors="replace").strip()
                raise SourceHardeningError(f"Unable to harden {relative}: {detail or 'PHP tokenizer failed'}")
            output = staging / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(result.stdout)
            lint = subprocess.run([executable, "-l", str(output)], capture_output=True, check=False)
            if lint.returncode != 0:
                detail = (lint.stderr or lint.stdout).decode("utf-8", errors="replace").strip()
                raise SourceHardeningError(f"Hardened file failed PHP lint: {relative}: {detail}")
        for relative in files:
            shutil.copyfile(staging / relative, root / relative)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return [root / relative for relative in files]
