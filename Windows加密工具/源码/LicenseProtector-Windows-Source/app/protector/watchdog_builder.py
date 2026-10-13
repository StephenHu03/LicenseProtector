from __future__ import annotations

import base64
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from app.license.schema import LicenseDocument


class WatchdogBuilder:
    """Build the protected files copied into a customer release.

    The loader deliberately contains only the verification path. Its public key
    is embedded in the generated file so a customer cannot replace a separate
    public-key file and sign a replacement license with their own private key.
    """

    def build(self, project_root: Path, document: LicenseDocument, public_key_path: Path) -> list[Path]:
        directory = project_root / "protected" / "watchdog"
        directory.mkdir(parents=True, exist_ok=True)
        public_pem = public_key_path.read_bytes()
        # PHP sodium requires the 32-byte raw Ed25519 public key. The PEM stays
        # on the vendor side; its raw public half is embedded in the loader.
        public_raw = serialization.load_pem_public_key(public_pem).public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        public_b64 = base64.b64encode(public_raw).decode("ascii")
        loader = '''<?php
/* LICENSE_PROTECTOR_BOOTSTRAP_V1 */
declare(strict_types=1);
$__lp_d = static function(string $v): string { $v = strtolower(trim($v)); if (strpos($v, '://') !== false) { $v = (string)(parse_url($v, PHP_URL_HOST) ?? ''); } else { $v = explode('/', $v, 2)[0]; $v = explode(':', $v, 2)[0]; } return rtrim($v, '.'); };
$__lp_i = static function(string $v): string { return filter_var(trim($v), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ?: ''; };
/* Hyperf includes this file from its request middleware. Calling exit() there
   aborts the Swoole worker and is surfaced to clients as HTTP 500. */
$__lp_from_middleware = isset($__lp_request_host);
$__lp_fail = static function(string $c, string $detail = '') use ($__lp_from_middleware) { error_log('license_id=' . (defined('LP_LICENSE_ID') ? LP_LICENSE_ID : 'unknown') . ' error_code=' . $c . ' detail=' . $detail . ' timestamp=' . gmdate('c')); if ($__lp_from_middleware) { throw new \\RuntimeException('License validation failed (' . $c . ')'); } http_response_code(403); exit('License validation failed (' . $c . ')'); };
$__lp_base = dirname(__DIR__, 2);
$__lp_license = $__lp_base . '/license.dat';
if (!is_file($__lp_license)) { $__lp_fail('LIC-1001'); }
$__lp_raw = json_decode((string)file_get_contents($__lp_license), true);
if (!is_array($__lp_raw) || !isset($__lp_raw['signature'])) { $__lp_fail('LIC-1006'); }
$__lp_sig = base64_decode((string)$__lp_raw['signature'], true);
$__lp_payload = $__lp_raw; unset($__lp_payload['signature']);
/* LicenseSigner writes keys in lexical order; PHP preserves decoded object order.
   JSON_SORT_KEYS is unavailable on PHP 8.3, so do not require it at runtime. */
$__lp_canon = json_encode($__lp_payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
$__lp_public = base64_decode('__LP_PUBLIC_KEY__', true);
/* Ed25519 is intentionally verified by PHP's built-in sodium extension. OpenSSL's
   generic digest API does not support Ed25519 on all PHP 8.x builds. */
$__lp_ok = function_exists('sodium_crypto_sign_verify_detached') && is_string($__lp_sig) && is_string($__lp_public) && strlen($__lp_public) === 32 && sodium_crypto_sign_verify_detached($__lp_sig, (string)$__lp_canon, $__lp_public);
if (!$__lp_ok && !function_exists('sodium_crypto_sign_verify_detached')) { $__lp_fail('LIC-1007'); }
if (!$__lp_ok) { $__lp_fail('LIC-1002'); }
if (!defined('LP_LICENSE_ID')) { define('LP_LICENSE_ID', (string)$__lp_payload['license_id']); }
$__lp_php_min = (string)($__lp_payload['php_min_version'] ?? '8.0');
$__lp_php_parts = explode('.', $__lp_php_min, 3);
$__lp_php_required = ((int)($__lp_php_parts[0] ?? 0) * 10000) + ((int)($__lp_php_parts[1] ?? 0) * 100);
if ($__lp_php_required < 80000 || PHP_VERSION_ID < $__lp_php_required) { $__lp_fail('LIC-1007', 'php_version'); }
$__lp_exp = $__lp_payload['expires_at'] ?? null;
if ($__lp_exp && strtotime((string)$__lp_exp) <= time()) { $__lp_fail('LIC-1005'); }
/*
 * Hyperf starts bin/hyperf.php through CLI, which has no HTTP Host. Its
 * generated middleware includes this loader for every request and provides
 * $__lp_request_host in that include scope. Traditional PHP validates here.
 */
$__lp_require_binding = PHP_SAPI !== 'cli' || isset($__lp_request_host);
if ($__lp_require_binding) {
    $__lp_host = $__lp_d((string)($__lp_request_host ?? $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? ''));
    $__lp_domains = $__lp_payload['domains'] ?? [($__lp_payload['domain'] ?? '')]; if (!is_array($__lp_domains)) { $__lp_domains = []; }
    $__lp_dm = false; foreach ($__lp_domains as $__lp_allowed_domain) { if ($__lp_host !== '' && $__lp_host === $__lp_d((string)$__lp_allowed_domain)) { $__lp_dm = true; break; } }
    $__lp_server_ips = [];
    foreach (gethostbynamel(gethostname()) ?: [] as $__lp_x) { if ($__lp_i($__lp_x) !== '') { $__lp_server_ips[] = $__lp_i($__lp_x); } }
    $__lp_cfg = $__lp_i((string)($_SERVER['SERVER_ADDR'] ?? '')); if ($__lp_cfg !== '') { $__lp_server_ips[] = $__lp_cfg; }
    $__lp_license_ips = $__lp_payload['ipv4s'] ?? [($__lp_payload['ipv4'] ?? '')]; if (!is_array($__lp_license_ips)) { $__lp_license_ips = []; }
    $__lp_im = false; foreach ($__lp_license_ips as $__lp_allowed_ip) { $__lp_want_ip = $__lp_i((string)$__lp_allowed_ip); foreach ($__lp_server_ips as $__lp_x) { if ($__lp_want_ip !== '' && $__lp_x === $__lp_want_ip) { $__lp_im = true; break 2; } } }
    if (!$__lp_dm && !$__lp_im) { $__lp_fail(!empty($__lp_license_ips) && !$__lp_server_ips ? 'LIC-1007' : 'LIC-1003', 'target_mismatch'); }
}
$__lp_manifest = $__lp_base . '/MANIFEST';
$__lp_manifest_sig = $__lp_base . '/protected/watchdog/manifest.sig';
if (!is_file($__lp_manifest) || !is_file($__lp_manifest_sig)) { $__lp_fail('LIC-1008'); }
$__lp_manifest_bytes = file_get_contents($__lp_manifest);
$__lp_manifest_signature = base64_decode((string)file_get_contents($__lp_manifest_sig), true);
if (!is_string($__lp_manifest_bytes) || !is_string($__lp_manifest_signature) || !sodium_crypto_sign_verify_detached($__lp_manifest_signature, $__lp_manifest_bytes, $__lp_public)) { $__lp_fail('LIC-1008'); }
$___lp_m = json_decode($__lp_manifest_bytes, true); if (!is_array($___lp_m) || !isset($___lp_m['files']) || !is_array($___lp_m['files'])) { $__lp_fail('LIC-1008'); } foreach ($___lp_m['files'] as $__lp_f => $__lp_h) { if (!is_string($__lp_f) || !is_string($__lp_h) || !is_file($__lp_base . '/' . $__lp_f) || hash_file('sha256', $__lp_base . '/' . $__lp_f) !== $__lp_h) { $__lp_fail('LIC-1008'); } }
?>
'''.replace('__LP_PUBLIC_KEY__', public_b64).replace('$___lp_domain', '$__lp_domain').replace('$___lp_m', '$__lp_m')
        (directory / "loader.php").write_text(loader, encoding="utf-8", newline="\n")
        return [directory / "loader.php"]
