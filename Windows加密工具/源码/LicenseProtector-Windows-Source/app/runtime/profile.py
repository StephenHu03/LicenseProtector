"""Runtime contract for the PHP + Hyperf protection implementation."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RuntimeProfile:
    """A buildable language/framework pair and its supported PHP baselines."""

    language: str
    framework: str
    minimum_versions: tuple[str, ...]

    def normalize_php_min_version(self, value: str) -> str:
        """Validate the selected server baseline before it is signed."""
        candidate = value.strip().removesuffix("+")
        if candidate not in self.minimum_versions:
            options = ", ".join(f"PHP {item}+" for item in self.minimum_versions)
            raise ValueError(f"Unsupported PHP baseline. Choose one of: {options}")
        return candidate

    def validate_project_framework(self, detected: str) -> None:
        if detected != self.framework:
            raise ValueError(f"This release supports {self.framework} projects only; detected: {detected}")


# The generated loader deliberately uses PHP 8.0-compatible syntax. Sodium is
# checked at runtime because it depends on the target server build, not source.
PHP_HYPERF = RuntimeProfile("PHP", "Hyperf", ("8.0", "8.1", "8.2", "8.3", "8.4"))
