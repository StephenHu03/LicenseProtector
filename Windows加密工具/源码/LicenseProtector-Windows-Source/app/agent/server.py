"""Linux Agent for the native Loader protocol.

The production deployment should run this process as a dedicated system user
with a Unix socket mode restricted to the PHP service account. It returns only
the currently authorized, authenticated payload; the runtime key never leaves
this process. The native PHP Loader executes that payload in memory.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import socketserver
import threading
from typing import Any

from app.license.signer import LicenseSigner
from app.validation.domain import domain_matches
from app.protector.lpbc import decode_container, load_runtime_key


PROTOCOL = "LP-AGENT-1"
LPBC_PREFIX = "protected/lpbc/"


class AgentError(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentConfig:
    socket_path: Path
    runtime_key_path: Path
    license_path: Path
    public_key_path: Path
    manifest_path: Path
    manifest_signature_path: Path
    socket_mode: int = 0o660
    server_ipv4s: tuple[str, ...] = ()


class LicenseAgent:
    def __init__(self, config: AgentConfig):
        self.config = config
        self._server: socketserver.ThreadingUnixStreamServer | None = None
        self._stop = threading.Event()

    def _read_manifest(self) -> tuple[dict[str, Any], bytes]:
        manifest_bytes = self.config.manifest_path.read_bytes()
        signature = self.config.manifest_signature_path.read_text(encoding="ascii").strip()
        public_key = LicenseSigner.load_public(self.config.public_key_path)
        if not LicenseSigner.verify_bytes(manifest_bytes, signature, public_key):
            raise AgentError("native manifest signature invalid")
        try:
            manifest = json.loads(manifest_bytes)
        except json.JSONDecodeError as exc:
            raise AgentError("native manifest malformed") from exc
        if not isinstance(manifest, dict) or manifest.get("protocol") != "LP-NATIVE-1":
            raise AgentError("unsupported native manifest")
        expected_key = str(manifest.get("runtime_key_sha256", ""))
        if expected_key != hashlib.sha256(self.config.runtime_key_path.read_bytes()).hexdigest():
            raise AgentError("runtime key fingerprint mismatch")
        return manifest, manifest_bytes

    def _verify_manifest_files(self, manifest: dict[str, Any]) -> None:
        delivery_root = self.config.manifest_path.resolve().parents[2]
        for item in manifest.get("files", []):
            if not isinstance(item, dict):
                raise AgentError("native manifest file entry malformed")
            relative = str(item.get("path", ""))
            if not relative or relative.startswith("/") or ".." in Path(relative).parts:
                raise AgentError("native manifest path invalid")
            target = (delivery_root / Path(relative)).resolve()
            try:
                target.relative_to(delivery_root)
            except ValueError as exc:
                raise AgentError("native manifest path escapes delivery") from exc
            if not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != str(item.get("sha256", "")):
                raise AgentError(f"native manifest file changed: {relative}")

    def _verify_license(self, request: dict[str, Any], allow_bootstrap: bool = False) -> None:
        document = LicenseSigner.read(self.config.license_path)
        if not LicenseSigner.verify(document, LicenseSigner.load_public(self.config.public_key_path)):
            raise AgentError("license signature invalid")
        if document.payload.expires_at:
            expiry = datetime.fromisoformat(document.payload.expires_at.replace("Z", "+00:00"))
            if expiry <= datetime.now(timezone.utc):
                raise AgentError("license expired")
        request_host = str(request.get("host", ""))
        domain_ok = any(domain_matches(request_host, allowed) for allowed in document.payload.domains)
        licensed_ips = set(document.payload.ipv4s)
        server_ips = set(self.config.server_ipv4s)
        if not server_ips:
            try:
                server_ips.update(
                    item[4][0]
                    for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
                    if item[4] and item[4][0]
                )
            except OSError:
                pass
        request_ip_ok = any(domain_matches(request_host, allowed) for allowed in licensed_ips)
        if not domain_ok and not request_ip_ok and not licensed_ips.intersection(server_ips):
            # Hyperf may load protected classes before the HTTP server accepts
            # requests, when no Host header exists yet. The middleware performs
            # a strict per-request check before serving traffic.
            if allow_bootstrap and not request_host:
                return
            raise AgentError("license target mismatch")

    def authorize(self, request: dict[str, Any]) -> dict[str, Any]:
        if request.get("protocol") != PROTOCOL or request.get("op") != "authorize":
            raise AgentError("unsupported agent request")
        manifest, manifest_bytes = self._read_manifest()
        self._verify_license(request, allow_bootstrap=manifest.get("framework") == "hyperf")
        if request.get("manifest_sha256") != hashlib.sha256(manifest_bytes).hexdigest():
            raise AgentError("manifest digest mismatch")
        path = str(request.get("path", ""))
        files = manifest.get("files", [])
        allowed = {str(item.get("path")): str(item.get("sha256")) for item in files if isinstance(item, dict)}
        if path not in allowed:
            raise AgentError("file is not in the signed native manifest")
        if not path.startswith(LPBC_PREFIX) or not path.endswith(".lpbc"):
            raise AgentError("invalid LPBC artifact path")
        delivery_root = self.config.manifest_path.resolve().parents[2]
        artifact_path = (delivery_root / Path(path)).resolve()
        try:
            artifact_path.relative_to(delivery_root)
        except ValueError as exc:
            raise AgentError("invalid LPBC artifact path") from exc
        if not artifact_path.is_file():
            raise AgentError("LPBC artifact digest mismatch")
        artifact_bytes = artifact_path.read_bytes()
        if hashlib.sha256(artifact_bytes).hexdigest() != allowed[path]:
            raise AgentError("LPBC artifact digest mismatch")
        source_path = path[len(LPBC_PREFIX):-len(".lpbc")] + ".php"
        try:
            header, payload = decode_container(
                artifact_bytes,
                load_runtime_key(self.config.runtime_key_path),
                LicenseSigner.load_public(self.config.public_key_path),
            )
        except ValueError as exc:
            raise AgentError("LPBC signature or decryption failed") from exc
        if header.path != source_path:
            raise AgentError("LPBC source path mismatch")
        response = {
            "protocol": PROTOCOL,
            "ok": True,
            "path": path,
            "file_sha256": allowed[path],
            "source_path": source_path,
            "payload_type": header.payload_type,
        }
        if request.get("check_only") is not True:
            response["payload_b64"] = __import__("base64").b64encode(payload).decode("ascii")
        return response

    def validate_host(self, request: dict[str, Any]) -> dict[str, Any]:
        if request.get("protocol") != PROTOCOL or request.get("op") != "validate":
            raise AgentError("unsupported agent request")
        self._verify_license(request)
        manifest, manifest_bytes = self._read_manifest()
        if request.get("manifest_sha256") != hashlib.sha256(manifest_bytes).hexdigest():
            raise AgentError("manifest digest mismatch")
        self._verify_manifest_files(manifest)
        return {"protocol": PROTOCOL, "ok": True}

    def handle_line(self, line: bytes) -> bytes:
        try:
            request = json.loads(line.decode("utf-8"))
            if not isinstance(request, dict):
                raise AgentError("request must be an object")
            operation = request.get("op")
            if operation == "authorize":
                response = self.authorize(request)
            elif operation == "validate":
                response = self.validate_host(request)
            else:
                raise AgentError("unsupported agent operation")
        except (AgentError, OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            response = {"protocol": PROTOCOL, "ok": False, "error": str(exc)}
        return (json.dumps(response, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")

    def serve_forever(self) -> None:
        path = self.config.socket_path
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            metadata = path.lstat()
            if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.geteuid():
                raise AgentError(f"Refusing to replace non-owned socket path: {path}")
            path.unlink()
        agent = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                line = self.rfile.readline(1024 * 1024)
                if line:
                    self.wfile.write(agent.handle_line(line))

        class Server(socketserver.ThreadingUnixStreamServer):
            daemon_threads = True
            allow_reuse_address = True

        server = Server(str(path), Handler)
        self._server = server
        os.chmod(path, self.config.socket_mode)
        try:
            server.serve_forever(poll_interval=0.2)
        finally:
            server.server_close()
            try:
                metadata = path.lstat()
                if stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == os.geteuid():
                    path.unlink()
            except FileNotFoundError:
                pass

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
