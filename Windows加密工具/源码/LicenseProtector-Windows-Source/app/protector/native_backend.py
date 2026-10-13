"""Self-hosted Encoder and delivery builder for the native Loader protocol."""

from __future__ import annotations

from collections.abc import Iterable
import json
from pathlib import Path
import shutil
import tempfile

from app.license.signer import LicenseSigner
from app.license.schema import LicensePayload
from app.protector.lpbc import encode_file, load_runtime_key
from app.protector.native_manifest import write_native_manifest
from app.protector.ir import compile_php_to_ir
from app.injector.hyperf_injector import HyperfInjector


_IGNORED_DIRECTORY_NAMES = {".git", ".hg", ".svn", "node_modules", "vendor", "__pycache__"}
_HYPERF_MIDDLEWARE_CONFIG = Path("config/autoload/middlewares.php")
_NATIVE_MIDDLEWARE_SOURCE = Path("app/Middleware/NativeLicenseProtectorMiddleware.php")


def normalize_native_paths(project_root: Path, selections: Iterable[Path]) -> tuple[Path, ...]:
    """Expand selections without encoding dependencies, VCS data, or external symlinks."""
    root = project_root.resolve()
    selected: list[Path] = []
    for raw in selections:
        lexical_candidate = raw if raw.is_absolute() else root / raw
        if lexical_candidate.is_symlink():
            raise ValueError(f"Selected PHP source must not be a symlink: {lexical_candidate}")
        candidate = lexical_candidate
        try:
            candidate = candidate.resolve()
            candidate.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"Selected source must be inside the project: {raw}") from exc
        if candidate.is_dir():
            files = sorted(candidate.rglob("*.php"))
            for file in files:
                if not file.is_file():
                    continue
                relative = file.relative_to(root)
                if any(part.lower() in _IGNORED_DIRECTORY_NAMES for part in relative.parts[:-1]):
                    continue
                if file.is_symlink():
                    raise ValueError(f"Selected PHP source must not be a symlink: {file}")
                try:
                    file.resolve().relative_to(root)
                except ValueError as exc:
                    raise ValueError(f"Selected PHP source escapes the project through a symlink: {file}") from exc
                selected.append(relative)
        elif candidate.is_file() and candidate.suffix.lower() == ".php":
            selected.append(candidate.relative_to(root))
        else:
            raise ValueError(f"Selected source must be a PHP file or directory: {raw}")
    return tuple(dict.fromkeys(selected))


def _validate_hyperf_integration(project_root: Path, paths: tuple[Path, ...]) -> bool:
    """Validate middleware integration before creating a delivery directory."""
    composer = project_root / "composer.json"
    requires_hyperf = False
    if composer.is_file():
        try:
            metadata = json.loads(composer.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Unable to read project composer.json: {exc}") from exc
        if not isinstance(metadata, dict):
            raise ValueError("Project composer.json must contain a JSON object")
        for section in ("require", "require-dev"):
            requirements = metadata.get(section, {})
            if isinstance(requirements, dict) and any(
                isinstance(package, str) and package.lower().startswith("hyperf/")
                for package in requirements
            ):
                requires_hyperf = True
                break

    config_path = project_root / _HYPERF_MIDDLEWARE_CONFIG
    is_hyperf = requires_hyperf or config_path.is_file()
    if not is_hyperf:
        return False
    if not config_path.is_file():
        raise ValueError("Hyperf project is missing config/autoload/middlewares.php")
    if _HYPERF_MIDDLEWARE_CONFIG in paths:
        raise ValueError(
            "Do not select config/autoload/middlewares.php for protection; Native build must update it to register the license guard"
        )
    if _NATIVE_MIDDLEWARE_SOURCE in paths or (project_root / _NATIVE_MIDDLEWARE_SOURCE).exists():
        raise ValueError(
            "Project already contains app/Middleware/NativeLicenseProtectorMiddleware.php; rename it before building"
        )
    return True


def encode_selected_files(
    project_root: Path,
    selections: Iterable[Path],
    output_root: Path,
    private_key_path: Path,
    runtime_key_path: Path | None = None,
    payload_type: str = "php-source-v1",
) -> tuple[list[Path], Path]:
    """Encode selected PHP files and return artifacts plus Agent key path."""
    root = project_root.resolve()
    if output_root.is_symlink():
        raise ValueError("Delivery output directory must not be a symlink")
    delivery_root = output_root.resolve()
    try:
        delivery_root.relative_to(root)
    except ValueError:
        pass
    else:
        raise ValueError("Delivery output directory must be outside the source project")
    paths = normalize_native_paths(root, selections)
    if not paths:
        raise ValueError("At least one PHP file or directory must be selected for native encoding")
    signing_key = LicenseSigner.load_private(private_key_path)
    if runtime_key_path is None:
        raise ValueError("runtime_key_path is required; never place the Agent key inside the delivery directory")
    key_path = runtime_key_path.resolve()
    try:
        key_path.relative_to(root)
    except ValueError:
        pass
    else:
        raise ValueError("Agent runtime key must be outside the project directory")
    try:
        key_path.relative_to(delivery_root)
    except ValueError:
        pass
    else:
        raise ValueError("Agent runtime key must be outside the delivery directory")
    if not key_path.is_file():
        raise FileNotFoundError(
            f"Agent runtime key not found: {key_path}. Run agent-keygen first and provision it to the Linux Agent."
        )
    runtime_key = load_runtime_key(key_path)
    compiled: list[tuple[Path, bytes]] = []
    for relative in paths:
        try:
            source = (root / relative).read_bytes()
            ir_payload = compile_php_to_ir(source) if payload_type == "ir-v1" else source
        except ValueError as exc:
            raise ValueError(f"Cannot encode {relative.as_posix()} as {payload_type}: {exc}") from exc
        compiled.append((relative, ir_payload))

    artifacts: list[Path] = []
    for relative, ir_payload in compiled:
        destination = output_root / "protected" / "lpbc" / relative.with_suffix(".lpbc")
        encode_file(root / relative, root, destination, runtime_key, signing_key, payload_type, ir_payload)
        artifacts.append(destination)
    write_native_manifest(output_root, artifacts, root, key_path, private_key_path)
    return artifacts, key_path


def build_native_delivery(
    project_root: Path,
    selections: Iterable[Path],
    output_root: Path,
    private_key_path: Path,
    runtime_key_path: Path,
    license_id: str,
    product_version: str,
    domains: tuple[str, ...] = (),
    ipv4s: tuple[str, ...] = (),
    php_min_version: str = "8.1",
) -> Path:
    """Build a runnable delivery with source files replaced by Loader shims."""
    root = project_root.resolve()
    if output_root.is_symlink():
        raise ValueError("Delivery output directory must not be a symlink")
    output = output_root.resolve()
    if output == root or root in output.parents:
        raise ValueError("Delivery output directory must be outside the source project")
    if not root.is_dir():
        raise NotADirectoryError(f"Project directory not found: {root}")
    paths = normalize_native_paths(root, selections)
    if not paths:
        raise ValueError("At least one PHP file or directory must be selected")
    is_hyperf = _validate_hyperf_integration(root, paths)
    project_key = private_key_path.resolve()
    try:
        project_key.relative_to(root)
    except ValueError:
        pass
    else:
        raise ValueError("Vendor private signing key must be outside the source project")
    agent_key = runtime_key_path.resolve()
    for protected_path, label in ((project_key, "vendor private signing key"), (agent_key, "Agent runtime key")):
        try:
            protected_path.relative_to(root)
        except ValueError:
            pass
        else:
            raise ValueError(f"{label} must be outside the source project")
        try:
            protected_path.relative_to(output)
        except ValueError:
            pass
        else:
            raise ValueError(f"{label} must be outside the delivery directory")
    if output.exists():
        if not output.is_dir() or any(output.iterdir()):
            raise ValueError(f"Delivery output directory must be empty: {output}")
    LicenseSigner.load_private(private_key_path)
    if not agent_key.is_file():
        raise FileNotFoundError(f"Agent runtime key not found: {agent_key}")
    load_runtime_key(agent_key)
    if not domains and not ipv4s:
        raise ValueError("At least one license domain or IPv4 is required")
    LicensePayload.create(license_id, product_version, domains, ipv4s, php_min_version=php_min_version)

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{output.name}.build-", dir=output.parent) as temporary:
        staging = Path(temporary)
        shutil.copytree(root, staging, dirs_exist_ok=True)
        artifacts, _ = encode_selected_files(root, paths, staging, private_key_path, runtime_key_path, "php-source-v1")
        tracked_paths: list[Path] = []
        for relative in paths:
            shim_path = staging / relative
            artifact_relative = Path("protected/lpbc") / relative.with_suffix(".lpbc")
            # The shim's __DIR__ is the source file's directory; walk back to the
            # delivery root before entering protected/lpbc.
            prefix = "../" * len(relative.parent.parts)
            shim_path.write_text(
                "<?php\n"
                "if (!function_exists('lpbc_execute')) {\n"
                "    throw new RuntimeException('LicenseProtector native Loader extension is not loaded');\n"
                "}\n"
                f"return lpbc_execute(__DIR__ . '/{prefix}{artifact_relative.as_posix()}', "
                "getenv('LP_AGENT_SOCKET') ?: '/run/license-protector/agent.sock', "
                "$_SERVER['HTTP_HOST'] ?? getenv('LICENSE_HOST') ?? '');\n",
                encoding="utf-8",
            )
            tracked_paths.append(shim_path)
        # Hyperf loads protected classes before HTTP requests; this guard checks
        # each request Host once the server receives traffic.
        if is_hyperf:
            tracked_paths.extend(HyperfInjector().inject_native(staging))
        write_native_manifest(
            staging,
            artifacts,
            root,
            agent_key,
            private_key_path,
            php_min_version,
            tracked_paths=tracked_paths,
            framework="hyperf" if is_hyperf else "php",
        )
        write_native_license(staging, private_key_path, license_id, product_version, domains, ipv4s, php_min_version)
        if output.exists():
            output.rmdir()
        staging.replace(output)
    return output


def write_native_license(
    output_root: Path,
    private_key_path: Path,
    license_id: str,
    product_version: str,
    domains: tuple[str, ...] = (),
    ipv4s: tuple[str, ...] = (),
    php_min_version: str = "8.1",
    product_id: str = "PRODUCT-001",
) -> Path:
    """Create the signed license required by the Linux Agent."""
    if not domains and not ipv4s:
        raise ValueError("At least one license domain or IPv4 is required")
    private_key = LicenseSigner.load_private(private_key_path)
    payload = LicensePayload.create(
        license_id,
        product_version,
        domains,
        ipv4s,
        product_id,
        php_min_version=php_min_version,
    )
    path = output_root / "license.dat"
    LicenseSigner.write(LicenseSigner.sign(payload, private_key), path)
    return path
