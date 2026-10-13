from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZIP_DEFLATED, ZipFile
import os
import shutil
import uuid

from app.injector.bootstrap_injector import BootstrapInjector
from app.injector.hyperf_injector import HyperfInjector
from app.license.schema import LicensePayload
from app.license.signer import LicenseSigner
from app.license.targets import LicenseTargets
from app.protector.integrity_builder import build_manifest
from app.protector.php_hardener import harden_php_sources, normalize_source_paths
from app.protector.watchdog_builder import WatchdogBuilder
from app.runtime.profile import PHP_HYPERF
from app.scanner.project_scanner import ProjectScanner, ProjectInfo


@dataclass(frozen=True)
class BuildRequest:
    project: Path
    domains: tuple[str, ...]
    ipv4s: tuple[str, ...]
    php_min_version: str
    product_version: str
    output: Path
    private_key: Path
    public_key: Path
    product_id: str = "PRODUCT-001"
    license_id: str | None = None
    entry: Path | None = None
    hardened_paths: tuple[Path, ...] = ()
    php_executable: str = "php"


@dataclass(frozen=True)
class BuildResult:
    release_dir: Path
    zip_path: Path
    license_id: str
    project_info: ProjectInfo


def _extended_path(path: Path) -> str:
    r"""返回 Windows 长路径形式，避免深层 vendor 文件触发 WinError 3。

    Windows 的传统 Win32 API 默认限制路径长度为 260 个字符。客户项目
    常见的 Composer SDK（例如腾讯云 SDK）目录层级很深，历史交付目录再
    叠加时间戳后容易超过该限制。``\\?\`` 前缀会启用 Windows 扩展路径 API；
    非 Windows 平台保持普通路径，便于开发和测试。
    """
    raw = os.path.abspath(os.fspath(path))
    if os.name != "nt" or raw.startswith("\\\\?\\"):
        return raw
    if raw.startswith("\\\\"):
        return "\\\\?\\UNC\\" + raw[2:]
    return "\\\\?\\" + raw


def _normal_path(path: str) -> str:
    """移除扩展路径前缀，仅用于计算 ZIP 内部的相对文件名。"""
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[8:]
    if path.startswith("\\\\?\\"):
        return path[4:]
    return path


def _copytree(source: Path, destination: Path) -> None:
    """复制整个项目，并对 Windows 源路径和目标路径启用长路径支持。"""
    shutil.copytree(_extended_path(source), _extended_path(destination))


def _remove_tree(path: Path) -> None:
    """删除可能超过 260 字符的历史目录。"""
    shutil.rmtree(_extended_path(path))


def _iter_files(path: Path):
    """遍历长路径目录，返回可直接交给 ZipFile 的文件路径。"""
    root = _extended_path(path)
    for current, _directories, files in os.walk(root):
        for name in files:
            yield os.path.join(current, name)


class PackageBuilder:
    def __init__(self, logger=None):
        self.log = logger or (lambda message: None)

    def build(self, request: BuildRequest) -> BuildResult:
        project = request.project.resolve()
        targets = LicenseTargets.create(request.domains, request.ipv4s)
        php_min_version = PHP_HYPERF.normalize_php_min_version(request.php_min_version)
        if not request.private_key.is_file() or not request.public_key.is_file():
            raise FileNotFoundError("Signing key files are required")
        private_key = LicenseSigner.load_private(request.private_key)
        public_key = LicenseSigner.load_public(request.public_key)
        if not LicenseSigner.keys_match(private_key, public_key):
            raise ValueError("Signing private key does not match the selected public key")
        info = ProjectScanner().scan(project, request.entry)
        PHP_HYPERF.validate_project_framework(info.framework)
        hardened_paths = normalize_source_paths(project, request.hardened_paths)
        license_id = request.license_id or f"LIC-{__import__('datetime').datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        payload = LicensePayload.create(
            license_id,
            request.product_version,
            targets.domains,
            targets.ipv4s,
            request.product_id,
            php_min_version=php_min_version,
        )
        document = LicenseSigner.sign(payload, private_key)
        request.output.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(prefix="license-protector-") as temp:
            workspace = Path(temp) / project.name
            _copytree(project, workspace)
            self.log("项目已复制到临时工作区")
            hardened_files = harden_php_sources(workspace, hardened_paths, request.php_executable)
            if hardened_files:
                self.log(f"已加固 {len(hardened_files)} 个选中的 PHP 文件")
            LicenseSigner.write(document, workspace / "license.dat")
            protected = WatchdogBuilder().build(workspace, document, request.public_key)
            BootstrapInjector().inject(workspace, workspace / info.entry.relative_to(project))
            # Hyperf starts the selected entry from CLI. Generate a middleware
            # so the request Host is checked when actual HTTP traffic arrives.
            framework_files = HyperfInjector().inject(workspace) if info.framework == "Hyperf" else []
            protected_files = [p for p in protected + framework_files + hardened_files if p.is_file()]
            manifest = workspace / "MANIFEST"
            build_manifest(workspace, protected_files + [workspace / "license.dat"], manifest)
            # The manifest must be signed separately: otherwise a modified PHP
            # checker and a recomputed list of hashes could be deployed together.
            manifest_signature = LicenseSigner.sign_bytes(manifest.read_bytes(), private_key)
            (workspace / "protected" / "watchdog" / "manifest.sig").write_text(
                manifest_signature + "\n", encoding="ascii", newline="\n"
            )
            (workspace / "VERSION").write_text(request.product_version + "\n", encoding="utf-8")
            install_notes = (
                "LicenseProtector delivery\n\n"
                "Runtime: PHP + Hyperf\n"
                f"Minimum PHP version: {php_min_version}+\n"
                "The signed license accepts any one of its listed domains or IPv4 addresses.\n"
                "The server must enable the sodium extension. Hyperf projects validate Host in the generated middleware.\n"
                "No network connection is required.\n"
            )
            (workspace / "INSTALL.md").write_text(install_notes, encoding="utf-8")
            # Every build gets an immutable archive directory. This prevents a
            # later customer build from overwriting an earlier deliverable.
            release_name = f"{project.name}_Release_{request.product_version}"
            history_name = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + license_id
            history_dir = request.output / "history" / history_name
            history_dir.mkdir(parents=True, exist_ok=True)
            release_dir = history_dir / release_name
            if release_dir.exists():
                _remove_tree(release_dir)
            _copytree(workspace, release_dir)
            zip_path = history_dir / f"{release_name}.zip"
            with ZipFile(zip_path, "w", ZIP_DEFLATED) as archive:
                for item in _iter_files(release_dir):
                    # item 使用扩展路径打开，归档名则使用普通相对路径。
                    archive_name = os.path.relpath(_normal_path(item), history_dir)
                    archive.write(item, archive_name.replace(os.sep, "/"))
        self.log(f"打包完成: {zip_path}")
        return BuildResult(release_dir, zip_path, license_id, info)
