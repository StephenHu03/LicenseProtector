from pathlib import Path
import base64
import hashlib
import json
import shutil
import subprocess
import zipfile

from cryptography.hazmat.primitives import serialization
import pytest
from app.license.schema import LicensePayload
from app.license.signer import LicenseSigner
from app.license.verifier import validate_document, LicenseValidationError
from app.license.targets import LicenseTargets
from app.validation.domain import domain_matches
from app.validation.ipv4 import ipv4_matches
from app.injector.hyperf_injector import HyperfInjector
from app.package.builder import BuildRequest, PackageBuilder
from app.protector.php_hardener import harden_php_sources, normalize_source_paths
from app.protector.lpbc import LPBCError, create_runtime_key, decode_container, derive_file_key, encode_source
from app.protector.native_backend import build_native_delivery, encode_selected_files, write_native_license
from app.protector.deployment_bundle import build_linux_deployment_bundle, build_linux_source_bundle
from app.protector.ir import IRCompileError, compile_php_to_ir
from app.agent.server import AgentConfig, LicenseAgent
from app.cli import _configured_server_ipv4s


def test_native_loader_includes_generated_vendor_key_config():
    repo_root = Path(__file__).resolve().parents[1]
    workspace_root = repo_root.parents[2]
    loader_sources = (
        repo_root / "native" / "loader" / "license_loader.c",
        workspace_root / "Linux授权服务端" / "源码" / "LicenseProtector-Linux-Agent" / "native" / "loader" / "license_loader.c",
    )
    for source in loader_sources:
        lines = source.read_text(encoding="utf-8").splitlines()
        assert '#include "config.h"' in lines
        assert lines.index('#include "config.h"') < lines.index("#include <php.h>")
        text = "\n".join(lines)
        assert "Z_TYPE_P(object) == IS_OBJECT" in text
        assert "zend_string_init((const char *)bytes, len, 0)" in text
        assert "php_json_decode_ex(result, ZSTR_VAL(json), ZSTR_LEN(json)" in text
        assert "JSON_G(error_code) != PHP_JSON_ERROR_NONE" in text
        assert "JSON_G(error_code)" in text
        assert "manifest JSON type=%d error=%d" in text
        for stage in (
            "signature encoding",
            "signature verification",
            "manifest JSON",
            "manifest protocol",
            "artifact read",
            "artifact manifest hash",
        ):
            assert stage in text


def test_domain_and_ip_are_exact():
    assert domain_matches("https://Customer.Example.com:443/path", "customer.example.com")
    assert not domain_matches("evilcustomer.example.com", "customer.example.com")
    assert ipv4_matches(["10.0.0.2", "192.168.1.2"], "192.168.1.2")
    assert not ipv4_matches(["192.168.1.20"], "192.168.1.2")


def test_multiple_targets_are_normalized_and_deduplicated():
    targets = LicenseTargets.create(
        "HTTPS://Api.Example.com:443, api.example.com\nadmin.example.com.",
        "10.0.3.6; 10.0.3.6\n192.168.1.10",
    )
    assert targets.domains == ("api.example.com", "admin.example.com")
    assert targets.ipv4s == ("10.0.3.6", "192.168.1.10")


@pytest.mark.skipif(shutil.which("php") is None, reason="PHP CLI is required for free source hardening")
def test_selected_php_sources_are_hardened_without_removing_doc_comments(tmp_path: Path):
    source = tmp_path / "app" / "Service" / "Critical.php"
    source.parent.mkdir(parents=True)
    source.write_text(
        "<?php\n/** Route metadata must survive. */\n// Ordinary comment\nfunction run( ) { return 1; }\n",
        encoding="utf-8",
    )

    paths = normalize_source_paths(tmp_path, [Path("app")])
    assert paths == (Path("app/Service/Critical.php"),)
    hardened = harden_php_sources(tmp_path, paths)
    result = source.read_text(encoding="utf-8")

    assert hardened == [source]
    assert "Route metadata must survive." in result
    assert "Ordinary comment" not in result


def test_lpbc_round_trip_and_tamper_rejection(tmp_path: Path):
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    LicenseSigner.generate_keypair(private, public)
    private_key, public_key = LicenseSigner.load_private(private), LicenseSigner.load_public(public)
    runtime_key = b"k" * 32
    encoded = encode_source(b"<?php return 42;", "app/Service/Core.php", runtime_key, private_key)

    header, source = decode_container(encoded, runtime_key, public_key)
    assert header.path == "app/Service/Core.php"
    assert header.payload_type == "php-source-v1"
    assert source == b"<?php return 42;"
    assert derive_file_key(runtime_key, "app/Service/Core.php") != derive_file_key(runtime_key, "app/Service/Other.php")
    with pytest.raises(LPBCError):
        decode_container(encoded[:-1] + bytes([encoded[-1] ^ 1]), runtime_key, public_key)
    with pytest.raises(LPBCError):
        decode_container(encoded, b"x" * 32, public_key)


def test_native_backend_requires_external_agent_key_and_writes_lpbc(tmp_path: Path):
    project = tmp_path / "project"
    source = project / "app" / "Service" / "Core.php"
    source.parent.mkdir(parents=True)
    source.write_text("<?php return 42;\n", encoding="utf-8")
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    LicenseSigner.generate_keypair(private, public)
    runtime_key = tmp_path / "agent" / "runtime.key"
    create_runtime_key(runtime_key)
    output = tmp_path / "delivery"

    artifacts, key_path = encode_selected_files(project, [Path("app/Service/Core.php")], output, private, runtime_key, payload_type="ir-v1")
    assert artifacts == [output / "protected" / "lpbc" / "app" / "Service" / "Core.lpbc"]
    assert key_path == runtime_key.resolve()
    assert artifacts[0].is_file()
    assert not (output / "agent-runtime.key").exists()
    manifest = output / "protected" / "lpbc" / "manifest.json"
    signature = output / "protected" / "lpbc" / "manifest.sig"
    assert manifest.is_file() and signature.is_file()
    assert LicenseSigner.verify_bytes(manifest.read_bytes(), signature.read_text(encoding="ascii").strip(), LicenseSigner.load_public(public))
    header, payload = decode_container(artifacts[0].read_bytes(), runtime_key.read_bytes(), LicenseSigner.load_public(public))
    assert header.payload_type == "ir-v1"
    assert b'"ir":"LP-IR-1"' in payload
    assert runtime_key.read_bytes().hex() not in manifest.read_text(encoding="utf-8")
    license_path = write_native_license(output, private, "LIC-NATIVE", "1.0.0", ("example.com",), ())
    assert license_path == output / "license.dat"
    assert LicenseSigner.verify(LicenseSigner.read(license_path), LicenseSigner.load_public(public))
    with pytest.raises(ValueError, match="outside the delivery directory"):
        encode_selected_files(project, [Path("app/Service/Core.php")], output, private, output / "runtime.key")
    with pytest.raises(ValueError, match="outside the source project"):
        encode_selected_files(project, [Path("app/Service/Core.php")], project / "generated", private, runtime_key)


def test_linux_deployment_bundle_contains_only_project_runtime_material(tmp_path: Path):
    private, public = tmp_path / "vendor_private.pem", tmp_path / "vendor_public.pem"
    LicenseSigner.generate_keypair(private, public)
    runtime_key = tmp_path / "runtime.key"
    create_runtime_key(runtime_key)
    bundle = build_linux_deployment_bundle(
        tmp_path / "linux-install.zip", runtime_key, private, public
    )

    with zipfile.ZipFile(bundle) as archive:
        names = set(archive.namelist())
        assert "LicenseProtector-Linux-Installer/runtime.key" in names
        assert "LicenseProtector-Linux-Installer/vendor_public.pem" in names
        assert "LicenseProtector-Linux-Installer/install.sh" in names
        assert "LicenseProtector-Linux-Installer/app/agent/server.py" in names
        assert "LicenseProtector-Linux-Installer/native/loader/license_loader.c" in names
        assert not any("vendor_private" in name or name.endswith("private.pem") for name in names)
        assert archive.read("LicenseProtector-Linux-Installer/runtime.key") == runtime_key.read_bytes()
        assert b"/opt/license-protector-agent" in archive.read("LicenseProtector-Linux-Installer/install.sh")

    other_private, other_public = tmp_path / "other-private.pem", tmp_path / "other-public.pem"
    LicenseSigner.generate_keypair(other_private, other_public)
    with pytest.raises(ValueError, match="不匹配"):
        build_linux_deployment_bundle(
            tmp_path / "should-not-exist.zip", runtime_key, private, other_public
        )
    assert not (tmp_path / "should-not-exist.zip").exists()


def test_linux_source_bundle_has_agent_loader_and_no_project_secrets(tmp_path: Path):
    bundle = build_linux_source_bundle(tmp_path / "linux-source.zip")
    with zipfile.ZipFile(bundle) as archive:
        names = set(archive.namelist())
        assert "LicenseProtector-Linux-Agent/app/agent/server.py" in names
        assert "LicenseProtector-Linux-Agent/native/loader/license_loader.c" in names
        assert "LicenseProtector-Linux-Agent/deploy/install-linux.sh" in names
        assert not any(name.endswith("runtime.key") or "vendor_private" in name for name in names)
        assert not any("/gui/" in name or "/package/" in name for name in names)


def test_ir_compiler_fails_closed_for_untrusted_php():
    assert b'"op":"RETURN"' in compile_php_to_ir(b"<?php return 42;")
    assert b'"op":"CALL_NATIVE"' in compile_php_to_ir(b"<?php return strlen('abc');")
    assert b'"value":"a,b"' in compile_php_to_ir(b"<?php return trim('a,b');")
    with pytest.raises(IRCompileError):
        compile_php_to_ir(b"<?php echo $_POST['x'];")
    with pytest.raises(IRCompileError, match="allowlist"):
        compile_php_to_ir(b"<?php return system('id');")


def test_native_delivery_replaces_selected_source_with_loader_shim(tmp_path: Path):
    project = tmp_path / "project"
    source = project / "app" / "Service" / "Core.php"
    source.parent.mkdir(parents=True)
    source.write_text("<?php\nfinal class Core { public function run(): int { return 42; } }\n", encoding="utf-8")
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    LicenseSigner.generate_keypair(private, public)
    runtime_key = tmp_path / "agent" / "runtime.key"
    create_runtime_key(runtime_key)
    delivery = tmp_path / "delivery"
    build_native_delivery(project, [Path("app/Service/Core.php")], delivery, private, runtime_key, "LIC-RUN", "1.0.0", ("example.com",))
    shim = (delivery / "app" / "Service" / "Core.php").read_text(encoding="utf-8")
    assert "lpbc_execute" in shim
    assert "Core {" not in shim
    assert "../../protected/lpbc/app/Service/Core.lpbc" in shim
    assert (delivery / "protected" / "lpbc" / "app" / "Service" / "Core.lpbc").is_file()
    assert (delivery / "license.dat").is_file()
    assert not (delivery / "private.pem").exists()
    with pytest.raises(ValueError, match="private signing key must be outside the source project"):
        build_native_delivery(project, [Path("app/Service/Core.php")], tmp_path / "bad-delivery", project / "signing.pem", runtime_key, "LIC-RUN", "1.0.0", ("example.com",))

    root_project = tmp_path / "root-project"
    root_project.mkdir()
    (root_project / "index.php").write_text("<?php return 1;\n", encoding="utf-8")
    root_delivery = tmp_path / "root-delivery"
    build_native_delivery(root_project, [Path("index.php")], root_delivery, private, runtime_key, "LIC-ROOT", "1.0.0", ("example.com",))
    assert "protected/lpbc/index.lpbc" in (root_delivery / "index.php").read_text(encoding="utf-8")


def test_native_directory_selection_skips_vendor_and_vcs_trees(tmp_path: Path):
    project = tmp_path / "project"
    for relative in (
        "app/Service/Core.php",
        "vendor/package/Runtime.php",
        ".git/hooks/sample.php",
        "node_modules/package/index.php",
    ):
        source = project / relative
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("<?php return 1;\n", encoding="utf-8")
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    LicenseSigner.generate_keypair(private, public)
    runtime_key = tmp_path / "agent" / "runtime.key"
    create_runtime_key(runtime_key)

    output = tmp_path / "encoded"
    artifacts, _ = encode_selected_files(project, [Path(".")], output, private, runtime_key)

    assert [path.relative_to(output).as_posix() for path in artifacts] == [
        "protected/lpbc/app/Service/Core.lpbc"
    ]


def test_native_directory_selection_rejects_php_symlinks(tmp_path: Path):
    project = tmp_path / "project"
    source = project / "app" / "Service" / "Core.php"
    source.parent.mkdir(parents=True)
    source.write_text("<?php return 1;\n", encoding="utf-8")
    alias = project / "app" / "Service" / "Alias.php"
    try:
        alias.symlink_to(source)
    except (OSError, NotImplementedError):
        pytest.skip("PHP source symlinks are unavailable on this platform")
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    LicenseSigner.generate_keypair(private, public)
    runtime_key = tmp_path / "agent" / "runtime.key"
    create_runtime_key(runtime_key)

    with pytest.raises(ValueError, match="must not be a symlink"):
        encode_selected_files(project, [Path("app")], tmp_path / "encoded", private, runtime_key)


def test_native_outputs_reject_directory_symlinks(tmp_path: Path):
    project = tmp_path / "project"
    source = project / "app" / "Core.php"
    source.parent.mkdir(parents=True)
    source.write_text("<?php return 1;\n", encoding="utf-8")
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    LicenseSigner.generate_keypair(private, public)
    runtime_key = tmp_path / "agent" / "runtime.key"
    create_runtime_key(runtime_key)
    target = tmp_path / "actual-output"
    target.mkdir()
    alias = tmp_path / "output-link"
    try:
        alias.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Directory symlinks are unavailable on this platform")

    with pytest.raises(ValueError, match="output directory must not be a symlink"):
        encode_selected_files(project, [Path("app/Core.php")], alias, private, runtime_key)
    with pytest.raises(ValueError, match="output directory must not be a symlink"):
        build_native_delivery(
            project,
            [Path("app/Core.php")],
            alias,
            private,
            runtime_key,
            "LIC-SYMLINK",
            "1.0.0",
            ("example.com",),
        )
    assert not any(target.iterdir())


def test_native_hyperf_build_rejects_guard_conflicts_before_output(tmp_path: Path):
    project = tmp_path / "project"
    (project / "config" / "autoload").mkdir(parents=True)
    (project / "config" / "autoload" / "middlewares.php").write_text("<?php return ['http' => []];\n", encoding="utf-8")
    (project / "app" / "Middleware").mkdir(parents=True)
    (project / "app" / "Middleware" / "NativeLicenseProtectorMiddleware.php").write_text("<?php\n", encoding="utf-8")
    source = project / "app" / "Service" / "Core.php"
    source.parent.mkdir(parents=True)
    source.write_text("<?php return 1;\n", encoding="utf-8")
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    LicenseSigner.generate_keypair(private, public)
    runtime_key = tmp_path / "agent" / "runtime.key"
    create_runtime_key(runtime_key)
    delivery = tmp_path / "delivery"

    with pytest.raises(ValueError, match="Do not select config/autoload/middlewares.php"):
        build_native_delivery(
            project,
            [Path("app/Service/Core.php"), Path("config/autoload/middlewares.php")],
            delivery,
            private,
            runtime_key,
            "LIC-CONFLICT",
            "1.0.0",
            ("example.com",),
        )
    assert not delivery.exists()

    with pytest.raises(ValueError, match="already contains app/Middleware/NativeLicenseProtectorMiddleware.php"):
        build_native_delivery(
            project,
            [Path("app/Service/Core.php")],
            delivery,
            private,
            runtime_key,
            "LIC-CONFLICT",
            "1.0.0",
            ("example.com",),
        )
    assert not delivery.exists()


def test_native_hyperf_build_requires_middleware_configuration(tmp_path: Path):
    project = tmp_path / "hyperf-project"
    project.mkdir()
    (project / "composer.json").write_text('{"require":{"hyperf/framework":"~3.0"}}', encoding="utf-8")
    source = project / "app" / "Service" / "Core.php"
    source.parent.mkdir(parents=True)
    source.write_text("<?php return 1;\n", encoding="utf-8")
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    LicenseSigner.generate_keypair(private, public)
    runtime_key = tmp_path / "agent" / "runtime.key"
    create_runtime_key(runtime_key)
    delivery = tmp_path / "delivery"

    with pytest.raises(ValueError, match="missing config/autoload/middlewares.php"):
        build_native_delivery(
            project,
            [Path("app/Service/Core.php")],
            delivery,
            private,
            runtime_key,
            "LIC-HYPERF-MISSING",
            "1.0.0",
            ("example.com",),
        )
    assert not delivery.exists()


def test_agent_authorizes_only_signed_manifest_files(tmp_path: Path):
    project = tmp_path / "project"
    source = project / "app" / "Service" / "Core.php"
    source.parent.mkdir(parents=True)
    source.write_text("<?php return 42;\n", encoding="utf-8")
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    LicenseSigner.generate_keypair(private, public)
    runtime_key = tmp_path / "agent" / "runtime.key"
    create_runtime_key(runtime_key)
    output = tmp_path / "delivery"
    artifacts, _ = encode_selected_files(project, [Path("app/Service/Core.php")], output, private, runtime_key)
    license_document = LicenseSigner.sign(
        LicensePayload.create("LIC-AGENT", "1.0.0", "example.com", None),
        LicenseSigner.load_private(private),
    )
    license_path = output / "license.dat"
    LicenseSigner.write(license_document, license_path)
    manifest = output / "protected" / "lpbc" / "manifest.json"
    signature = output / "protected" / "lpbc" / "manifest.sig"
    agent = LicenseAgent(AgentConfig(
        socket_path=tmp_path / "agent.sock",
        runtime_key_path=runtime_key,
        license_path=license_path,
        public_key_path=public,
        manifest_path=manifest,
        manifest_signature_path=signature,
    ))
    request = {
        "protocol": "LP-AGENT-1",
        "op": "authorize",
        "host": "example.com",
        "path": "protected/lpbc/app/Service/Core.lpbc",
        "manifest_sha256": __import__("hashlib").sha256(manifest.read_bytes()).hexdigest(),
    }
    request["host"] = ""
    denied_bootstrap = json.loads(agent.handle_line((json.dumps(request) + "\n").encode("utf-8")))
    assert denied_bootstrap["ok"] is False
    request["host"] = "example.com"
    response = json.loads(agent.handle_line((json.dumps(request) + "\n").encode("utf-8")))
    assert response["ok"] is True
    assert response["source_path"] == "app/Service/Core.php"
    assert base64.b64decode(response["payload_b64"]).replace(b"\r\n", b"\n") == b"<?php return 42;\n"
    assert "key_b64" not in response
    request["path"] = "protected/lpbc/unknown.lpbc"
    denied = json.loads(agent.handle_line((json.dumps(request) + "\n").encode("utf-8")))
    assert denied["ok"] is False
    request["path"] = "protected/lpbc/app/Service/Core.lpbc"
    request["host"] = "unauthorized.example.net"
    denied_host = json.loads(agent.handle_line((json.dumps(request) + "\n").encode("utf-8")))
    assert denied_host["ok"] is False
    request["host"] = "example.com"
    artifacts[0].write_bytes(artifacts[0].read_bytes() + b"tampered")
    denied_artifact = json.loads(agent.handle_line((json.dumps(request) + "\n").encode("utf-8")))
    assert denied_artifact["ok"] is False


def test_agent_accepts_domain_host_when_configured_server_ip_matches_license(tmp_path: Path):
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    LicenseSigner.generate_keypair(private, public)
    document = LicenseSigner.sign(
        LicensePayload.create("LIC-IP-BOUND", "1.0.0", None, ("203.0.113.10",)),
        LicenseSigner.load_private(private),
    )
    license_path = tmp_path / "license.dat"
    LicenseSigner.write(document, license_path)
    agent = LicenseAgent(AgentConfig(
        socket_path=tmp_path / "agent.sock",
        runtime_key_path=tmp_path / "runtime.key",
        license_path=license_path,
        public_key_path=public,
        manifest_path=tmp_path / "manifest.json",
        manifest_signature_path=tmp_path / "manifest.sig",
        server_ipv4s=("203.0.113.10",),
    ))

    agent._verify_license({"host": "api.example.com"})


def test_agent_server_ipv4_environment_accepts_multiple_separators(monkeypatch):
    monkeypatch.setenv("LP_SERVER_IPV4S", "203.0.113.10; 10.0.0.2,192.168.1.10")
    assert _configured_server_ipv4s() == ("203.0.113.10", "10.0.0.2", "192.168.1.10")


def test_native_hyperf_delivery_registers_and_verifies_request_guard(tmp_path: Path):
    project = tmp_path / "project"
    source = project / "app" / "Service" / "Core.php"
    source.parent.mkdir(parents=True)
    (project / "config" / "autoload").mkdir(parents=True)
    (project / "config" / "autoload" / "middlewares.php").write_text("<?php return ['http' => []];\n", encoding="utf-8")
    source.write_text("<?php final class Core { public function run(): int { return 42; } }\n", encoding="utf-8")
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    LicenseSigner.generate_keypair(private, public)
    runtime_key = tmp_path / "agent" / "runtime.key"
    create_runtime_key(runtime_key)
    delivery = tmp_path / "delivery"
    build_native_delivery(project, [Path("app/Service/Core.php")], delivery, private, runtime_key, "LIC-NATIVE-HYPERF", "1.0.0", ("example.com",))
    middleware = delivery / "app" / "Middleware" / "NativeLicenseProtectorMiddleware.php"
    config = delivery / "config" / "autoload" / "middlewares.php"
    assert middleware.is_file()
    assert "NativeLicenseProtectorMiddleware::class" in config.read_text(encoding="utf-8")
    manifest = json.loads((delivery / "protected/lpbc/manifest.json").read_text(encoding="utf-8"))
    assert manifest["framework"] == "hyperf"
    listed = {entry["path"] for entry in manifest["files"]}
    assert "app/Service/Core.php" in listed
    assert "app/Middleware/NativeLicenseProtectorMiddleware.php" in listed
    assert "config/autoload/middlewares.php" in listed
    php = shutil.which("php")
    if php:
        for php_file in (delivery / "app/Service/Core.php", middleware, config):
            lint = subprocess.run([php, "-l", str(php_file)], capture_output=True, text=True, check=False)
            assert lint.returncode == 0, lint.stderr or lint.stdout

    license_path = delivery / "license.dat"
    agent = LicenseAgent(AgentConfig(
        socket_path=tmp_path / "agent.sock",
        runtime_key_path=runtime_key,
        license_path=license_path,
        public_key_path=public,
        manifest_path=delivery / "protected/lpbc/manifest.json",
        manifest_signature_path=delivery / "protected/lpbc/manifest.sig",
    ))
    request = {
        "protocol": "LP-AGENT-1",
        "op": "validate",
        "host": "example.com",
        "manifest_sha256": hashlib.sha256((delivery / "protected/lpbc/manifest.json").read_bytes()).hexdigest(),
    }
    assert json.loads(agent.handle_line((json.dumps(request) + "\n").encode("utf-8")))['ok'] is True
    bootstrap_request = {
        "protocol": "LP-AGENT-1",
        "op": "authorize",
        "host": "",
        "path": "protected/lpbc/app/Service/Core.lpbc",
        "manifest_sha256": hashlib.sha256((delivery / "protected/lpbc/manifest.json").read_bytes()).hexdigest(),
    }
    assert json.loads(agent.handle_line((json.dumps(bootstrap_request) + "\n").encode("utf-8")))['ok'] is True
    config.write_text(config.read_text(encoding="utf-8") + "// changed\n", encoding="utf-8")
    assert json.loads(agent.handle_line((json.dumps(request) + "\n").encode("utf-8")))['ok'] is False


def test_ed25519_and_or_rule(tmp_path: Path):
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    other_private, other_public = tmp_path / "other-private.pem", tmp_path / "other-public.pem"
    LicenseSigner.generate_keypair(private, public)
    LicenseSigner.generate_keypair(other_private, other_public)
    payload = LicensePayload.create("LIC-TEST", "1.0.0", "customer.example.com", "203.0.113.10")
    private_key, public_key = LicenseSigner.load_private(private), LicenseSigner.load_public(public)
    document = LicenseSigner.sign(payload, private_key)
    assert LicenseSigner.keys_match(private_key, public_key)
    assert not LicenseSigner.keys_match(private_key, LicenseSigner.load_public(other_public))
    assert LicenseSigner.verify(document, public_key)
    assert LicenseSigner.verify_bytes(b"manifest", LicenseSigner.sign_bytes(b"manifest", private_key), public_key)
    validate_document(document, public_key, "wrong.example.com", ["203.0.113.10"])
    try:
        validate_document(document, public_key, "wrong.example.com", ["203.0.113.11"])
    except LicenseValidationError as error:
        assert error.code == "LIC-1003"
    else:
        raise AssertionError("mismatched domain and IP must fail")


def test_second_domain_and_ip_are_authorized(tmp_path: Path):
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    LicenseSigner.generate_keypair(private, public)
    payload = LicensePayload.create(
        "LIC-MULTI",
        "1.0.0",
        ["api.example.com", "admin.example.com"],
        ["10.0.3.6", "192.168.1.10"],
        php_min_version="8.1+",
    )
    document = LicenseSigner.sign(payload, LicenseSigner.load_private(private))
    assert document.payload.php_min_version == "8.1"
    assert document.payload.framework == "Hyperf"
    validate_document(document, LicenseSigner.load_public(public), "admin.example.com", ["127.0.0.1"])
    validate_document(document, LicenseSigner.load_public(public), "wrong.example.com", ["192.168.1.10"])


def test_hyperf_injector_registers_request_guard(tmp_path: Path):
    """Hyperf checks a request Host rather than its CLI worker startup."""
    config = tmp_path / "config" / "autoload" / "middlewares.php"
    config.parent.mkdir(parents=True)
    config.write_text("<?php\nreturn ['http' => [\\App\\Middleware\\CommonMiddleware::class]];\n", encoding="utf-8")

    generated = HyperfInjector().inject(tmp_path)
    middleware = tmp_path / "app" / "Middleware" / "LicenseProtectorMiddleware.php"

    assert middleware in generated
    assert config in generated
    middleware_text = middleware.read_text(encoding="utf-8")
    assert "$__lp_request_host = $request->getHeaderLine('Host');" in middleware_text
    assert "use Hyperf\\HttpServer\\Contract\\ResponseInterface as HyperfResponse;" in middleware_text
    assert "catch (\\RuntimeException $exception)" in middleware_text
    assert "->withStatus(403);" in middleware_text
    assert "\\App\\Middleware\\LicenseProtectorMiddleware::class" in config.read_text(encoding="utf-8")


def test_package_builder_rejects_mismatched_keypair(tmp_path: Path):
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    _other_private, other_public = tmp_path / "other-private.pem", tmp_path / "other-public.pem"
    LicenseSigner.generate_keypair(private, public)
    LicenseSigner.generate_keypair(_other_private, other_public)

    try:
        PackageBuilder().build(BuildRequest(
            project=tmp_path / "not-needed-before-key-validation",
            domains=("api.example.com",),
            ipv4s=(),
            php_min_version="8.1",
            product_version="1.0.0",
            output=tmp_path / "deliveries",
            private_key=private,
            public_key=other_public,
        ))
    except ValueError as error:
        assert "does not match" in str(error)
    else:
        raise AssertionError("a mismatched signing key pair must be rejected")


@pytest.mark.skipif(shutil.which("php") is None, reason="PHP CLI is required for free source hardening")
def test_hardened_delivery_files_are_signed(tmp_path: Path):
    project = tmp_path / "hyperf-demo"
    (project / "bin").mkdir(parents=True)
    (project / "app" / "Service").mkdir(parents=True)
    (project / "config" / "autoload").mkdir(parents=True)
    (project / "composer.json").write_text('{"require":{"hyperf/framework":"~3.0"}}', encoding="utf-8")
    (project / "bin" / "hyperf.php").write_text("<?php\necho 'start';\n", encoding="utf-8")
    (project / "app" / "Service" / "Critical.php").write_text(
        "<?php\n// Keep this implementation private\nfinal class Critical { public function run(): int { return 1; } }\n",
        encoding="utf-8",
    )
    (project / "config" / "autoload" / "middlewares.php").write_text("<?php\nreturn ['http' => []];\n", encoding="utf-8")
    private, public = tmp_path / "keys" / "private.pem", tmp_path / "keys" / "public.pem"
    LicenseSigner.generate_keypair(private, public)

    result = PackageBuilder().build(BuildRequest(
        project=project,
        domains=("api.example.com",),
        ipv4s=(),
        php_min_version="8.1",
        product_version="2.0.0",
        output=tmp_path / "deliveries",
        private_key=private,
        public_key=public,
        hardened_paths=(Path("app/Service/Critical.php"),),
    ))

    manifest_path = result.release_dir / "MANIFEST"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    delivered = (result.release_dir / "app" / "Service" / "Critical.php").read_text(encoding="utf-8")
    signature = (result.release_dir / "protected" / "watchdog" / "manifest.sig").read_text(encoding="ascii").strip()
    assert "app/Service/Critical.php" in manifest["files"]
    assert "Keep this implementation private" not in delivered
    assert LicenseSigner.verify_bytes(manifest_path.read_bytes(), signature, LicenseSigner.load_public(public))


def test_hyperf_delivery_contains_multiple_signed_targets(tmp_path: Path):
    """Exercise the complete build path without copying a production vendor tree."""
    project = tmp_path / "hyperf-demo"
    (project / "bin").mkdir(parents=True)
    (project / "app").mkdir()
    (project / "config" / "autoload").mkdir(parents=True)
    (project / "composer.json").write_text('{"require":{"hyperf/framework":"~3.0"}}', encoding="utf-8")
    (project / "bin" / "hyperf.php").write_text("<?php\necho 'start';\n", encoding="utf-8")
    (project / "config" / "autoload" / "middlewares.php").write_text("<?php\nreturn ['http' => []];\n", encoding="utf-8")
    private, public = tmp_path / "keys" / "private.pem", tmp_path / "keys" / "public.pem"
    LicenseSigner.generate_keypair(private, public)

    result = PackageBuilder().build(BuildRequest(
        project=project,
        domains=("api.example.com", "admin.example.com"),
        ipv4s=("10.0.3.6", "192.168.1.10"),
        php_min_version="8.1+",
        product_version="2.0.0",
        output=tmp_path / "deliveries",
        private_key=private,
        public_key=public,
    ))

    document = LicenseSigner.read(result.release_dir / "license.dat")
    manifest = json.loads((result.release_dir / "MANIFEST").read_text(encoding="utf-8"))
    manifest_path = result.release_dir / "MANIFEST"
    manifest_signature = (result.release_dir / "protected" / "watchdog" / "manifest.sig").read_text(encoding="ascii").strip()
    assert document.payload.domains == ("api.example.com", "admin.example.com")
    assert document.payload.ipv4s == ("10.0.3.6", "192.168.1.10")
    assert document.payload.php_min_version == "8.1"
    assert result.zip_path.is_file()
    assert "app/Middleware/LicenseProtectorMiddleware.php" in manifest["files"]
    assert "config/autoload/middlewares.php" in manifest["files"]
    assert "protected/watchdog/manifest.sig" not in manifest["files"]
    assert LicenseSigner.verify_bytes(manifest_path.read_bytes(), manifest_signature, LicenseSigner.load_public(public))
    assert not LicenseSigner.verify_bytes(manifest_path.read_bytes() + b" ", manifest_signature, LicenseSigner.load_public(public))
    assert not (result.release_dir / "protected" / "watchdog" / "public.key").exists()
    loader = (result.release_dir / "protected" / "watchdog" / "loader.php").read_text(encoding="utf-8")
    assert "$__lp_from_middleware = isset($__lp_request_host);" in loader
    assert "throw new \\RuntimeException('License validation failed (' . $c . ')');" in loader
    embedded_public = base64.b64encode(LicenseSigner.load_public(public).public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )).decode("ascii")
    assert f"base64_decode('{embedded_public}', true)" in loader
    assert "sodium_crypto_sign_verify_detached($__lp_manifest_signature, $__lp_manifest_bytes, $__lp_public)" in loader
