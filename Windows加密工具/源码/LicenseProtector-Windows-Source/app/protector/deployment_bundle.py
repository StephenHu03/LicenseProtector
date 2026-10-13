"""Build the project-specific Linux Agent installer bundle."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import sys
import tempfile
import zipfile

from app.license.signer import LicenseSigner
from app.protector.lpbc import load_runtime_key


_BUNDLE_FILES = (
    "LICENSE",
    "pyproject.toml",
    "requirements.txt",
    "deploy",
    "native",
)
_AGENT_APP_PARTS = ("__init__.py", "agent", "license", "runtime", "validation")
_AGENT_PROTECTOR_FILES = ("__init__.py", "lpbc.py")


def build_linux_deployment_bundle(
    output_path: Path,
    runtime_key_path: Path,
    private_key_path: Path,
    public_key_path: Path,
) -> Path:
    """Create an installer ZIP for one project; the ZIP contains its runtime key."""
    source_root = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[2]))
    runtime_key = runtime_key_path.resolve()
    private_path = private_key_path.resolve()
    public_path = public_key_path.resolve()
    load_runtime_key(runtime_key)
    private_key = LicenseSigner.load_private(private_path)
    public_key = LicenseSigner.load_public(public_path)
    if not LicenseSigner.keys_match(private_key, public_key):
        raise ValueError("厂商公钥与私钥不匹配，已停止生成 Linux 安装包")

    output = output_path.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.is_dir():
        raise IsADirectoryError(output)
    with tempfile.TemporaryDirectory(prefix="license-protector-bundle-") as temporary:
        staging = Path(temporary) / "LicenseProtector-Linux-Installer"
        staging.mkdir()
        _copy_linux_sources(source_root, staging)
        shutil.copy2(source_root / "deploy" / "install-linux.sh", staging / "install.sh")
        shutil.copy2(source_root / "deploy" / "部署手册-PHP环境自适应.md", staging / "部署手册-PHP环境自适应.md")
        shutil.copy2(runtime_key, staging / "runtime.key")
        shutil.copy2(public_path, staging / "vendor_public.pem")
        digest = hashlib.sha256(runtime_key.read_bytes()).hexdigest()
        (staging / "README-先看这里.txt").write_text(
            "LicenseProtector Linux 项目安装包\n\n"
            "此包含有该项目的 Agent 运行密钥，必须仅通过可信渠道传输，并限制服务器文件权限。\n"
            "厂商私钥不包含在本包中。请先把 Windows 生成的 PHP 加密交付内容放到原有项目目录，\n"
            "再根据服务器实际 PHP 版本选择匹配的 phpize/php-config。推荐使用项目仓库中的\n"
            "部署手册-PHP环境自适应.md 生成命令；最简执行方式为：\n"
            "sudo bash ./install.sh --project-root /你的/PHP项目路径 --php /实际使用的PHP/bin/php\n"
            "Loader 必须按目标 PHP 小版本重新编译，PHP 8.1 与 PHP 8.2 的扩展不能混用。\n"
            "CLI 与 PHP-FPM 可能读取不同 ini；FPM 报 socket 已占用时先检查宝塔已有 master 进程，\n"
            "不要重复启动或盲目结束未知 PHP/Hyperf 进程。\n\n"
            "固定安装位置：\n"
            "  Agent: /opt/license-protector-agent\n"
            "  密钥与配置: /etc/license-protector\n"
            "  Socket: /run/license-protector/agent.sock\n"
            f"运行密钥 SHA-256: {digest}\n",
            encoding="utf-8",
        )
        temporary_zip = output.with_suffix(output.suffix + ".tmp")
        try:
            _write_zip(staging, temporary_zip)
            os.replace(temporary_zip, output)
        finally:
            temporary_zip.unlink(missing_ok=True)
    return output


def build_linux_source_bundle(output_path: Path) -> Path:
    """Build a reusable Agent source archive with no project secrets."""
    source_root = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[2]))
    output = output_path.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.is_dir():
        raise IsADirectoryError(output)
    with tempfile.TemporaryDirectory(prefix="license-protector-linux-source-") as temporary:
        staging = Path(temporary) / "LicenseProtector-Linux-Agent"
        staging.mkdir()
        _copy_linux_sources(source_root, staging)
        shutil.copy2(source_root / "deploy" / "README.md", staging / "README.md")
        shutil.copy2(source_root / "deploy" / "部署手册-PHP环境自适应.md", staging / "部署手册-PHP环境自适应.md")
        temporary_zip = output.with_suffix(output.suffix + ".tmp")
        try:
            _write_zip(staging, temporary_zip)
            os.replace(temporary_zip, output)
        finally:
            temporary_zip.unlink(missing_ok=True)
    return output


def _copy_linux_sources(source_root: Path, staging: Path) -> None:
    for relative in _BUNDLE_FILES:
        source = source_root / relative
        target = staging / relative
        if not source.exists():
            raise FileNotFoundError(f"Linux deployment source missing: {source}")
        if source.is_dir():
            shutil.copytree(
                source,
                target,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache", "modules", ".libs"),
            )
        else:
            shutil.copy2(source, target)
    app_target = staging / "app"
    app_target.mkdir()
    for relative in _AGENT_APP_PARTS:
        source = source_root / "app" / relative
        target = app_target / relative
        if source.is_dir():
            shutil.copytree(
                source,
                target,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"),
            )
        else:
            shutil.copy2(source, target)
    protector_target = app_target / "protector"
    protector_target.mkdir()
    for relative in _AGENT_PROTECTOR_FILES:
        shutil.copy2(source_root / "app" / "protector" / relative, protector_target / relative)


def _write_zip(staging: Path, output: Path) -> None:
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for item in sorted(staging.rglob("*")):
            if item.is_file():
                archive.write(item, item.relative_to(staging.parent).as_posix())
