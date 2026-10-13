from __future__ import annotations

from pathlib import Path
import sys

repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root))

from app.protector.deployment_bundle import build_linux_source_bundle


workspace_root = repo_root.parents[2]
package_dir = workspace_root / "Linux授权服务端" / "安装包"
archive = package_dir / "Linux授权服务端-源码部署包.zip"

build_linux_source_bundle(archive)
print(f"Linux 源码包：{archive}")
