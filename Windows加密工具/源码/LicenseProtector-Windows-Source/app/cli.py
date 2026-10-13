from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
from app.license.signer import LicenseSigner
from app.protector.lpbc import create_runtime_key

DEVELOPER = "Stephen Hu <stephenhu031028@gmail.com>"


def _configured_server_ipv4s() -> tuple[str, ...]:
    return tuple(
        value.strip() for value in os.getenv("LP_SERVER_IPV4S", "").replace(";", ",").split(",") if value.strip()
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=f"Offline PHP LicenseProtector | Developer: {DEVELOPER}")
    sub = parser.add_subparsers(dest="command", required=True)
    keygen = sub.add_parser("keygen", help="Generate vendor Ed25519 key pair")
    keygen.add_argument("--private", required=True, type=Path)
    keygen.add_argument("--public", required=True, type=Path)
    build = sub.add_parser("build", help="Build a PHP + Hyperf customer release ZIP")
    for name in ("project", "private-key", "public-key", "output"):
        build.add_argument(f"--{name}", required=True, type=Path)
    build.add_argument("--domain", action="append", default=[], help="Authorized domain; repeat for multiple domains")
    build.add_argument("--ipv4", action="append", default=[], help="Authorized server IPv4; repeat for multiple addresses")
    build.add_argument("--harden-file", action="append", default=[], type=Path, help="Selected PHP file to harden; repeat as needed")
    build.add_argument("--harden-dir", action="append", default=[], type=Path, help="Directory whose PHP files will be hardened; repeat as needed")
    build.add_argument("--php-executable", default="php", help="Local PHP executable used for free source hardening")
    build.add_argument("--php-min-version", default="8.1", help="Target PHP baseline: 8.0, 8.1, 8.2, 8.3, or 8.4")
    build.add_argument("--version", required=True)
    encode = sub.add_parser("encode", help="Encode selected PHP files into self-hosted LPBC artifacts")
    encode.add_argument("--project", required=True, type=Path)
    encode.add_argument("--private-key", required=True, type=Path)
    encode.add_argument("--output", required=True, type=Path)
    encode.add_argument("--runtime-key", required=True, type=Path, help="Agent runtime key kept outside the delivery directory")
    encode.add_argument("--file", action="append", default=[], type=Path, help="Selected PHP file; repeat")
    encode.add_argument("--dir", action="append", default=[], type=Path, help="Selected PHP directory; repeat")
    encode.add_argument("--domain", action="append", default=[], help="Authorized domain; repeat")
    encode.add_argument("--ipv4", action="append", default=[], help="Authorized server IPv4; repeat")
    encode.add_argument("--version", required=True, help="Product version")
    encode.add_argument("--license-id", default=None)
    encode.add_argument("--php-min-version", default="8.1")
    native_build = sub.add_parser("native-build", help="Build a runnable native Loader delivery")
    native_build.add_argument("--project", required=True, type=Path)
    native_build.add_argument("--private-key", required=True, type=Path)
    native_build.add_argument("--output", required=True, type=Path)
    native_build.add_argument("--runtime-key", required=True, type=Path)
    native_build.add_argument("--file", action="append", default=[], type=Path)
    native_build.add_argument("--dir", action="append", default=[], type=Path)
    native_build.add_argument("--domain", action="append", default=[])
    native_build.add_argument("--ipv4", action="append", default=[])
    native_build.add_argument("--version", required=True)
    native_build.add_argument("--license-id", default=None)
    native_build.add_argument("--php-min-version", default="8.1")
    agent_keygen = sub.add_parser("agent-keygen", help="Generate an Agent runtime key outside a delivery directory")
    agent_keygen.add_argument("--output", required=True, type=Path)
    agent_serve = sub.add_parser("agent-serve", help="Run the Linux Unix-socket Agent")
    for name in ("socket", "runtime-key", "license", "public-key", "manifest", "manifest-signature"):
        agent_serve.add_argument(f"--{name}", required=True, type=Path)
    agent_serve.add_argument(
        "--server-ipv4",
        action="append",
        default=list(_configured_server_ipv4s()),
        help="Licensed server IPv4; repeat (or set LP_SERVER_IPV4S as a comma-separated list)",
    )
    agent_check = sub.add_parser("agent-check", help="Check a running Agent authorization socket")
    agent_check.add_argument("--socket", required=True, type=Path)
    agent_check.add_argument("--host", default="", help="HTTP Host/domain to authorize")
    agent_check.add_argument("--path", required=True, help="Signed LPBC path")
    agent_check.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()
    if args.command == "keygen":
        LicenseSigner.generate_keypair(args.private, args.public)
        print(f"Key pair generated. Developer: {DEVELOPER}")
        return 0
    if args.command == "agent-keygen":
        create_runtime_key(args.output)
        print(f"Agent runtime key generated: {args.output}")
        return 0
    if args.command == "agent-serve":
        from app.agent.server import AgentConfig, LicenseAgent

        LicenseAgent(AgentConfig(
            socket_path=args.socket,
            runtime_key_path=args.runtime_key,
            license_path=args.license,
            public_key_path=args.public_key,
            manifest_path=args.manifest,
            manifest_signature_path=args.manifest_signature,
            server_ipv4s=tuple(args.server_ipv4),
        )).serve_forever()
        return 0
    if args.command == "agent-check":
        request = {
            "protocol": "LP-AGENT-1",
            "op": "authorize",
            "host": args.host,
            "path": args.path,
            "manifest_sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
            "check_only": True,
        }
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(5)
            client.connect(str(args.socket))
            client.sendall((json.dumps(request, separators=(",", ":")) + "\n").encode("utf-8"))
            response = b""
            while not response.endswith(b"\n") and len(response) < 1024 * 1024:
                chunk = client.recv(65536)
                if not chunk:
                    break
                response += chunk
        document = json.loads(response.decode("utf-8"))
        print(json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if document.get("ok") is True else 1
    if args.command == "encode":
        from app.protector.native_backend import encode_selected_files, write_native_license

        artifacts, key_path = encode_selected_files(
            args.project,
            tuple(args.file + args.dir),
            args.output,
            args.private_key,
            args.runtime_key,
        )
        print(f"Encoded {len(artifacts)} file(s) into {args.output / 'protected' / 'lpbc'}")
        license_id = args.license_id or f"LIC-{__import__('datetime').datetime.now().strftime('%Y%m%d')}-{__import__('uuid').uuid4().hex[:6].upper()}"
        license_path = write_native_license(
            args.output,
            args.private_key,
            license_id,
            args.version,
            tuple(args.domain),
            tuple(args.ipv4),
            args.php_min_version,
        )
        print(f"Signed Agent license: {license_path}")
        print(f"Agent runtime key: {key_path}")
        return 0
    if args.command == "native-build":
        from app.protector.native_backend import build_native_delivery

        license_id = args.license_id or f"LIC-{__import__('datetime').datetime.now().strftime('%Y%m%d')}-{__import__('uuid').uuid4().hex[:6].upper()}"
        delivery = build_native_delivery(
            args.project,
            tuple(args.file + args.dir),
            args.output,
            args.private_key,
            args.runtime_key,
            license_id,
            args.version,
            tuple(args.domain),
            tuple(args.ipv4),
            args.php_min_version,
        )
        print(f"Native Loader delivery: {delivery}")
        print(f"License ID: {license_id}")
        return 0
    from app.package.builder import BuildRequest, PackageBuilder

    request = BuildRequest(
        project=args.project,
        domains=tuple(args.domain),
        ipv4s=tuple(args.ipv4),
        php_min_version=args.php_min_version,
        product_version=args.version,
        output=args.output,
        private_key=args.private_key,
        public_key=args.public_key,
        hardened_paths=tuple(args.harden_file + args.harden_dir),
        php_executable=args.php_executable,
    )
    result = PackageBuilder(print).build(request)
    print(f"Release: {result.zip_path}\nLicense ID: {result.license_id}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
