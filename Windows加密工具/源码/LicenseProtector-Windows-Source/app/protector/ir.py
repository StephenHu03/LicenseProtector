"""Small, deliberately strict IR compiler for the optional native Loader mode.

This is not a PHP parser.  It accepts only a tiny, documented subset and
fails closed for anything else.  That property is important: silently
falling back to encrypted PHP source would turn the native delivery into a
false promise about source protection.
"""

from __future__ import annotations

import ast
import json
import re


class IRCompileError(ValueError):
    pass


_RETURN = re.compile(r"\A\s*<\?php\s+return\s+(.+?)\s*;\s*\Z", re.S)
_CALL_RETURN = re.compile(
    r"\A\s*<\?php\s+return\s+([A-Za-z_][A-Za-z0-9_\\]*)\s*\((.*?)\)\s*;\s*\z", re.S
)
_NATIVE_FUNCTIONS = {"strlen", "strtolower", "strtoupper", "trim", "hash", "json_encode"}


def _split_arguments(value: str) -> list[str]:
    if not value.strip():
        return []
    parts: list[str] = []
    start = 0
    quote: str | None = None
    for index, char in enumerate(value):
        if quote:
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char == ",":
            parts.append(value[start:index].strip())
            start = index + 1
    if quote:
        raise IRCompileError("unterminated string literal")
    parts.append(value[start:].strip())
    if any(not part for part in parts):
        raise IRCompileError("empty function argument")
    return parts


def _constant(value: str) -> object:
    value = value.strip()
    if value == "true":
        return True
    if value == "false":
        return False
    if value == "null":
        return None
    if re.fullmatch(r"-?(?:0|[1-9][0-9]*)", value):
        return int(value)
    if value.startswith(("'", '"')):
        if "\\" in value or (value.startswith('"') and "$" in value):
            raise IRCompileError("escaped or interpolated PHP strings are not supported by ir-v1")
        try:
            parsed = ast.literal_eval(value)
        except (SyntaxError, ValueError) as exc:
            raise IRCompileError("unsupported PHP string literal") from exc
        if not isinstance(parsed, str):
            raise IRCompileError("unsupported PHP literal")
        return parsed
    raise IRCompileError("only scalar return constants are supported by ir-v1")


def compile_php_to_ir(source: bytes) -> bytes:
    """Compile the supported PHP subset into canonical JSON IR bytes."""
    try:
        text = source.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IRCompileError("ir-v1 requires UTF-8 PHP source") from exc
    match = _CALL_RETURN.fullmatch(text)
    if match:
        name, args = match.groups()
        if "\\" in name or name.casefold() not in _NATIVE_FUNCTIONS:
            raise IRCompileError(f"native function is not in the ir-v1 allowlist: {name}")
        values = [_constant(part) for part in _split_arguments(args)]
        instructions = [{"op": "PUSH_CONST", "value": value} for value in values]
        instructions.append({"op": "CALL_NATIVE", "name": name, "argc": len(values)})
        instructions.append({"op": "RETURN"})
    else:
        match = _RETURN.fullmatch(text)
        if not match:
            raise IRCompileError("unsupported PHP for ir-v1; use a scalar return or one native function call")
        instructions = [{"op": "PUSH_CONST", "value": _constant(match.group(1))}, {"op": "RETURN"}]
    payload = {"ir": "LP-IR-1", "instructions": instructions}
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
