"""Linux service entry point; contains no encoder or desktop commands."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket

from app.agent.server import AgentConfig, LicenseAgent


def main() -> int:
    parser = argparse.ArgumentParser(description="LicenseProtector Linux authorization server")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("agent-serve")
    serve.add_argument("--config", type=Path, help="JSON service configuration installed by install.sh")
    for name in ("socket", "runtime-key", "license", "public-key", "manifest", "manifest-signature"):
        serve.add_argument(f"--{name}", type=Path)
    serve.add_argument(
        "--server-ipv4", action="append",
        default=[ip.strip() for ip in os.getenv("LP_SERVER_IPV4S", "").replace(";", ",").split(",") if ip.strip()],
    )
    check = commands.add_parser("agent-check")
    check.add_argument("--socket", required=True, type=Path)
    check.add_argument("--host", default="")
    check.add_argument("--path", required=True)
    check.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()
    if args.command == "agent-serve":
        if args.config:
            try:
                config = json.loads(args.config.read_text(encoding="utf-8"))
                if not isinstance(config, dict):
                    raise ValueError("configuration must be a JSON object")
                fields = {
                    "socket": "socket_path",
                    "runtime_key": "runtime_key_path",
                    "license": "license_path",
                    "public_key": "public_key_path",
                    "manifest": "manifest_path",
                    "manifest_signature": "manifest_signature_path",
                }
                paths = {name: Path(config[field]) for name, field in fields.items()}
                server_ipv4s = tuple(str(value) for value in config.get("server_ipv4s", ()))
            except (OSError, KeyError, TypeError, json.JSONDecodeError, ValueError) as exc:
                parser.error(f"invalid Agent config {args.config}: {exc}")
        else:
            names = ("socket", "runtime_key", "license", "public_key", "manifest", "manifest_signature")
            missing = [name.replace("_", "-") for name in names if getattr(args, name) is None]
            if missing:
                parser.error("agent-serve requires --config or all path options: " + ", ".join(missing))
            paths = {name: getattr(args, name) for name in names}
            server_ipv4s = tuple(args.server_ipv4)
        LicenseAgent(AgentConfig(
            socket_path=paths["socket"], runtime_key_path=paths["runtime_key"],
            license_path=paths["license"], public_key_path=paths["public_key"],
            manifest_path=paths["manifest"], manifest_signature_path=paths["manifest_signature"],
            server_ipv4s=server_ipv4s,
        )).serve_forever()
        return 0
    request = {
        "protocol": "LP-AGENT-1", "op": "authorize", "host": args.host,
        "path": args.path, "check_only": True,
        "manifest_sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
    }
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect(str(args.socket))
        client.sendall((json.dumps(request) + "\n").encode("utf-8"))
        response = b""
        while not response.endswith(b"\n") and len(response) < 1024 * 1024:
            chunk = client.recv(65536)
            if not chunk:
                break
            response += chunk
    document = json.loads(response.decode("utf-8"))
    print(json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if document.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
