#!/usr/bin/env bash
set -Eeuo pipefail

AGENT_ROOT=/opt/license-protector-agent
CONFIG_ROOT=/etc/license-protector
SOCKET_PATH=/run/license-protector/agent.sock
PROJECT_ROOT=
PHP_BIN=
PHP_FPM_SERVICE=
PHP_USER=
PHP_GROUP=
SERVER_IPV4S=()

fail() { printf 'LicenseProtector 安装失败：%s\n' "$*" >&2; exit 1; }
info() { printf '\n==> %s\n' "$*"; }
usage() {
  cat <<'EOF'
用法：sudo bash ./install.sh --project-root /原有/PHP项目路径 [选项]

选项：
  --php /path/to/php              指定运行项目的 PHP CLI
  --php-fpm-service 服务名        指定 PHP-FPM systemd 服务
  --php-user 用户名               指定 PHP-FPM 用户（默认自动检测，回退 www）
  --php-group 组名                指定 PHP-FPM 用户组（默认自动检测，回退 www）
  --server-ipv4 地址               添加服务器授权 IPv4，可重复指定
EOF
}

while (($#)); do
  case "$1" in
    --project-root) PROJECT_ROOT=${2:?缺少 --project-root 参数值}; shift 2 ;;
    --php) PHP_BIN=${2:?缺少 --php 参数值}; shift 2 ;;
    --php-fpm-service) PHP_FPM_SERVICE=${2:?缺少 --php-fpm-service 参数值}; shift 2 ;;
    --php-user) PHP_USER=${2:?缺少 --php-user 参数值}; shift 2 ;;
    --php-group) PHP_GROUP=${2:?缺少 --php-group 参数值}; shift 2 ;;
    --server-ipv4) SERVER_IPV4S+=("${2:?缺少 --server-ipv4 参数值}"); shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; fail "未知参数：$1" ;;
  esac
done

[[ $EUID -eq 0 ]] || fail "请使用 sudo 运行安装脚本"
[[ -n "$PROJECT_ROOT" ]] || fail "必须指定 PHP 项目路径；不会替你移动或改写项目目录"
[[ -d "$PROJECT_ROOT" ]] || fail "PHP 项目目录不存在：$PROJECT_ROOT"
PROJECT_ROOT=$(CDPATH= cd -- "$PROJECT_ROOT" && pwd -P)
[[ -f "$PROJECT_ROOT/license.dat" ]] || fail "项目目录缺少 license.dat；请先把加密交付内容放到原项目路径"
[[ -f "$PROJECT_ROOT/protected/lpbc/manifest.json" ]] || fail "项目目录缺少 protected/lpbc/manifest.json"
[[ -f "$PROJECT_ROOT/protected/lpbc/manifest.sig" ]] || fail "项目目录缺少 protected/lpbc/manifest.sig"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PAYLOAD_ROOT=$SCRIPT_DIR
[[ -f "$PAYLOAD_ROOT/runtime.key" && -f "$PAYLOAD_ROOT/vendor_public.pem" ]] || fail "安装包缺少项目密钥文件，请重新从 Windows 工具生成"

if [[ -z "$PHP_BIN" ]]; then
  for candidate in /www/server/php/*/bin/php; do
    if [[ -x "$candidate" ]]; then PHP_BIN=$candidate; break; fi
  done
fi
if [[ -z "$PHP_BIN" ]]; then PHP_BIN=$(command -v php || true); fi
[[ -n "$PHP_BIN" ]] || fail "未找到 PHP；请用 --php 指定项目实际使用的 PHP CLI"
if [[ "$PHP_BIN" != */* ]]; then PHP_BIN=$(command -v "$PHP_BIN" || true); fi
[[ -x "$PHP_BIN" ]] || fail "PHP 不可执行：$PHP_BIN"
PHP_DIR=$(CDPATH= cd -- "$(dirname -- "$PHP_BIN")" && pwd -P)
PHP_VERSION=$($PHP_BIN -r 'echo PHP_MAJOR_VERSION,".",PHP_MINOR_VERSION;') || fail "无法读取 PHP 版本"
PHP_CONFIG=${PHP_CONFIG:-$PHP_DIR/php-config}
PHPIZE=${PHPIZE:-$PHP_DIR/phpize}
[[ -x "$PHP_CONFIG" ]] || PHP_CONFIG=$(command -v php-config || true)
[[ -x "$PHPIZE" ]] || PHPIZE=$(command -v phpize || true)
[[ -n "$PHP_CONFIG" && -x "$PHP_CONFIG" ]] || fail "找不到与 PHP $PHP_VERSION 对应的 php-config；请先在宝塔安装该 PHP 版本的开发工具"
[[ -n "$PHPIZE" && -x "$PHPIZE" ]] || fail "找不到与 PHP $PHP_VERSION 对应的 phpize；请先在宝塔安装该 PHP 版本的开发工具"
CONFIG_VERSION=$("$PHP_CONFIG" --version)
[[ "${CONFIG_VERSION%.*}" == "$PHP_VERSION" ]] || fail "PHP 与 php-config 版本不匹配：PHP=$PHP_VERSION，php-config=$CONFIG_VERSION"
PHP_INCLUDE_DIR=$("$PHP_CONFIG" --include-dir) || fail "无法读取 PHP 开发头文件目录"
PHP_API_HEADER="$PHP_INCLUDE_DIR/Zend/zend_modules.h"
[[ -r "$PHP_API_HEADER" ]] || fail "缺少 PHP 模块 API 头文件：$PHP_API_HEADER"
PHP_API=$(awk '$1 == "#define" && $2 == "ZEND_MODULE_API_NO" {print $3; exit}' "$PHP_API_HEADER")
PHPIZE_API=$("$PHPIZE" -v | awk '/PHP Api Version/ {print $NF; exit}')
[[ -n "$PHP_API" && "$PHP_API" == "$PHPIZE_API" ]] || fail "phpize 与 php-config API 不一致"

if [[ -z "$PHP_FPM_SERVICE" ]]; then
  PHP_VERSION_COMPACT=${PHP_VERSION//./}
  for candidate in "php-fpm-$PHP_VERSION_COMPACT" "php${PHP_VERSION_COMPACT}-fpm" "php-fpm"; do
    if systemctl cat "$candidate" >/dev/null 2>&1; then PHP_FPM_SERVICE=$candidate; break; fi
  done
fi
FPM_BIN=$PHP_DIR/php-fpm
[[ -x "$FPM_BIN" ]] || FPM_BIN="$(dirname "$PHP_DIR")/sbin/php-fpm"
[[ -x "$FPM_BIN" ]] || fail "找不到目标 PHP 的 php-fpm"
FPM_CONFIG="$(dirname "$PHP_DIR")/etc/php-fpm.conf"
if [[ -z "$PHP_USER" || -z "$PHP_GROUP" ]]; then
  FPM_CONF=$($FPM_BIN -i 2>/dev/null | sed -n 's/^Loaded Configuration File => //p' | head -n 1 || true)
  for conf in "${FPM_CONF:-}" "${FPM_CONF%/*}/php-fpm.d/www.conf" "${FPM_CONF%/*}/php-fpm.conf"; do
    [[ -f "$conf" ]] || continue
    [[ -n "$PHP_USER" ]] || PHP_USER=$(sed -n 's/^[[:space:]]*user[[:space:]]*=[[:space:]]*//p' "$conf" | head -n 1 | tr -d '[:space:]')
    [[ -n "$PHP_GROUP" ]] || PHP_GROUP=$(sed -n 's/^[[:space:]]*group[[:space:]]*=[[:space:]]*//p' "$conf" | head -n 1 | tr -d '[:space:]')
  done
fi
PHP_USER=${PHP_USER:-www}
PHP_GROUP=${PHP_GROUP:-www}
getent passwd "$PHP_USER" >/dev/null || fail "PHP-FPM 用户不存在：$PHP_USER；可通过 --php-user 指定"
getent group "$PHP_GROUP" >/dev/null || fail "PHP-FPM 用户组不存在：$PHP_GROUP；可通过 --php-group 指定"

info "检查系统构建依赖"
for command_name in openssl base64 make pkg-config; do command -v "$command_name" >/dev/null || fail "缺少命令：$command_name"; done
pkg-config --exists libsodium || fail "缺少 libsodium 开发文件；请在宝塔/系统包管理器安装 libsodium-devel 后重试"

info "安装 Agent 到 $AGENT_ROOT"
if ! getent group license-agent >/dev/null; then groupadd --system license-agent; fi
if ! id license-agent >/dev/null 2>&1; then
  useradd --system --no-create-home --gid license-agent --shell /sbin/nologin license-agent
fi
install -d -o root -g root -m 0755 "$AGENT_ROOT"
install -d -o root -g "$PHP_GROUP" -m 0750 "$AGENT_ROOT/app"
cp -a "$PAYLOAD_ROOT/app/." "$AGENT_ROOT/app/"
install -d -o root -g root -m 0755 "$AGENT_ROOT/native"
cp -a "$PAYLOAD_ROOT/native/." "$AGENT_ROOT/native/"
install -d -o root -g root -m 0755 "$AGENT_ROOT/deploy"
cp -a "$PAYLOAD_ROOT/deploy/." "$AGENT_ROOT/deploy/"
install -m 0644 "$PAYLOAD_ROOT/pyproject.toml" "$AGENT_ROOT/pyproject.toml"
if [[ ! -x "$AGENT_ROOT/venv/bin/python" ]]; then
  python3 -m venv "$AGENT_ROOT/venv" || fail "无法创建 Python 环境；请安装 python3-venv"
fi
if ! "$AGENT_ROOT/venv/bin/python" -c 'import cryptography' >/dev/null 2>&1; then
  "$AGENT_ROOT/venv/bin/python" -m pip install 'cryptography>=41' || fail "安装 cryptography 失败；请检查服务器网络和 Python pip"
fi
PYTHONPATH="$AGENT_ROOT" "$AGENT_ROOT/venv/bin/python" -c 'import app.agent.cli, cryptography' || fail "Agent Python 依赖检查失败"

info "安全安装项目密钥"
install -d -o root -g license-agent -m 0750 "$CONFIG_ROOT"
chown root:license-agent "$CONFIG_ROOT"
chmod 0750 "$CONFIG_ROOT"
if [[ -f "$CONFIG_ROOT/runtime.key" ]]; then
  cmp -s "$PAYLOAD_ROOT/runtime.key" "$CONFIG_ROOT/runtime.key" || fail "固定服务目录已有不同运行密钥；拒绝覆盖，避免破坏其他项目授权"
  chown root:license-agent "$CONFIG_ROOT/runtime.key"
  chmod 0640 "$CONFIG_ROOT/runtime.key"
else
  install -o root -g license-agent -m 0640 "$PAYLOAD_ROOT/runtime.key" "$CONFIG_ROOT/runtime.key"
fi
if [[ -f "$CONFIG_ROOT/vendor_public.pem" ]]; then
  cmp -s "$PAYLOAD_ROOT/vendor_public.pem" "$CONFIG_ROOT/vendor_public.pem" || fail "固定服务目录已有不同厂商公钥；拒绝覆盖"
  chown root:license-agent "$CONFIG_ROOT/vendor_public.pem"
  chmod 0640 "$CONFIG_ROOT/vendor_public.pem"
else
  install -o root -g license-agent -m 0640 "$PAYLOAD_ROOT/vendor_public.pem" "$CONFIG_ROOT/vendor_public.pem"
fi

info "为当前 PHP 项目写入 Agent 配置"
python3 - "$CONFIG_ROOT/agent.json" "$SOCKET_PATH" "$CONFIG_ROOT/runtime.key" "$PROJECT_ROOT" "$CONFIG_ROOT/vendor_public.pem" "${SERVER_IPV4S[@]}" <<'PY'
import json
import sys
from pathlib import Path

target, socket_path, runtime_key, project_root, public_key, *server_ipv4s = sys.argv[1:]
root = Path(project_root)
config = {
    "socket_path": socket_path,
    "runtime_key_path": runtime_key,
    "license_path": str(root / "license.dat"),
    "public_key_path": public_key,
    "manifest_path": str(root / "protected/lpbc/manifest.json"),
    "manifest_signature_path": str(root / "protected/lpbc/manifest.sig"),
    "server_ipv4s": server_ipv4s,
}
Path(target).write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
chown root:license-agent "$CONFIG_ROOT/agent.json"
chmod 0640 "$CONFIG_ROOT/agent.json"

info "编译目标 PHP $PHP_VERSION 的 Native Loader"
export PHPIZE PHP_CONFIG
export PATH="$PHP_DIR:$PATH"
# phpize leaves configure/Makefile from the previous PHP ABI. Always clear the
# generated files so a PHP 8.1 build cannot be silently reused for PHP 8.2.
LOADER_DIR="$PAYLOAD_ROOT/native/loader"
(
  cd "$LOADER_DIR"
  "$PHPIZE" --clean >/dev/null 2>&1 || true
  rm -f configure config.h config.status Makefile Makefile.objects \
    libtool config.nice modules/license_loader.so
)
bash "$PAYLOAD_ROOT/native/build-linux.sh" "$CONFIG_ROOT/vendor_public.pem" || fail "Loader 编译失败；检查 PHP 开发头文件和 libsodium-devel"
EXTENSION_DIR=$($PHP_CONFIG --extension-dir)
[[ -d "$EXTENSION_DIR" ]] || fail "PHP 扩展目录不存在"
[[ ! -f "$EXTENSION_DIR/license_loader.so" ]] || cp -a "$EXTENSION_DIR/license_loader.so" "$EXTENSION_DIR/license_loader.so.before.$(date +%Y%m%d%H%M%S).bak"
[[ -f "$PAYLOAD_ROOT/native/loader/modules/license_loader.so" ]] || fail "Loader 构建产物不存在"
"$PHP_BIN" -n -d "extension=$PAYLOAD_ROOT/native/loader/modules/license_loader.so" "$PAYLOAD_ROOT/native/selfcheck.php" || fail "新 Loader ABI 自检失败，尚未替换已安装的扩展"
install -o root -g root -m 0755 "$PAYLOAD_ROOT/native/loader/modules/license_loader.so" "$EXTENSION_DIR/license_loader.so"
configure_loader_ini() {
  local ini=$1
  [[ -n "$ini" && -f "$ini" ]] || fail "无法定位 PHP 配置文件：$ini"
  local backup="${ini}.license-loader.before.$(date +%Y%m%d%H%M%S).bak"
  cp -a "$ini" "$backup"
  sed -i '/license_loader\.so/d' "$ini"
  printf '\nextension=%s/license_loader.so\n' "$EXTENSION_DIR" >> "$ini"
  info "已配置 Loader：$ini（备份：$backup）"
}
SCAN_DIR=$($PHP_BIN --ini 2>/dev/null | sed -n 's/^Scan for additional .ini files in: *//p' | head -n 1)
PHP_INI=""
if [[ -n "$SCAN_DIR" && "$SCAN_DIR" != "(none)" && -d "$SCAN_DIR" ]]; then
  rm -f "$SCAN_DIR/license_loader.ini"
  install -o root -g root -m 0644 /dev/null "$SCAN_DIR/license_loader.ini"
  printf 'extension=%s/license_loader.so\n' "$EXTENSION_DIR" > "$SCAN_DIR/license_loader.ini"
else
  PHP_INI=$($PHP_BIN --ini 2>/dev/null | sed -n 's/^Loaded Configuration File: *//p' | head -n 1)
  configure_loader_ini "$PHP_INI"
fi
FPM_INI=$($FPM_BIN -i 2>/dev/null | sed -n 's/^Loaded Configuration File => //p' | head -n 1 || true)
if [[ -n "$FPM_INI" && "$FPM_INI" != "$PHP_INI" ]]; then
  configure_loader_ini "$FPM_INI"
elif [[ -z "$FPM_INI" ]]; then
  fail "无法定位 PHP-FPM 使用的 php.ini；请用 $FPM_BIN -i 检查"
fi
"$PHP_BIN" "$PAYLOAD_ROOT/native/selfcheck.php" || fail "PHP Loader 自检未通过"

info "配置 systemd 服务"
install -d -o root -g root -m 0755 /etc/systemd/system
sed "s/^Group=.*/Group=$PHP_GROUP/" "$PAYLOAD_ROOT/deploy/license-agent.service" > /etc/systemd/system/license-agent.service
chmod 0644 /etc/systemd/system/license-agent.service
systemctl daemon-reload
systemctl enable --now license-agent
if [[ -n "$PHP_FPM_SERVICE" ]]; then
  # 宝塔可能已手动启动同一 FPM master。优先平滑 reload，避免重复 start
  # 抢占同一个 Unix socket；只有确实没有 master 时才 start。
  if systemctl is-active --quiet "$PHP_FPM_SERVICE"; then
    if systemctl reload "$PHP_FPM_SERVICE"; then
      FPM_ACTION="已 reload"
    else
      FPM_ACTION="reload 失败；请在宝塔手动 reload 对应 PHP-FPM"
      info "$FPM_ACTION"
    fi
  else
    find_fpm_master() {
      # Match the complete process title, never the awk command doing the lookup.
      ps -eo pid=,args= | awk -v title="php-fpm: master process ($FPM_CONFIG)" '
        { pid=$1; sub(/^[[:space:]]*[0-9]+[[:space:]]+/, ""); if ($0 == title) print pid }
      '
    }
    FPM_MASTER=$(find_fpm_master)
    if [[ -n "$FPM_MASTER" ]]; then
      "$FPM_BIN" -t -y "$FPM_CONFIG" >/dev/null || fail "PHP-FPM 配置检查失败；未发送 reload"
      FPM_ACTION="master 已变化或 reload 失败；请在宝塔手动 reload 对应 PHP-FPM"
      for attempt in 1 2; do
        FPM_MASTER=$(find_fpm_master)
        [[ "$FPM_MASTER" =~ ^[0-9]+$ ]] || break
        if kill -USR2 "$FPM_MASTER" 2>/dev/null; then
          FPM_ACTION="检测到已有 master $FPM_MASTER，已发送平滑 reload"
          break
        fi
      done
      info "$FPM_ACTION"
    else
      systemctl start "$PHP_FPM_SERVICE"
      FPM_ACTION="已启动"
    fi
  fi
fi

info "验证 Agent 和授权清单"
systemctl is-active --quiet license-agent || fail "Agent 服务没有启动；运行 journalctl -u license-agent 查看原因"
ARTIFACT_REL=$(python3 - "$PROJECT_ROOT/protected/lpbc/manifest.json" <<'PY'
import json
import sys
from pathlib import PurePosixPath

manifest = json.load(open(sys.argv[1], encoding="utf-8"))
for item in manifest.get("files", []):
    path = str(item.get("path", ""))
    if path.startswith("protected/lpbc/") and path.endswith(".lpbc"):
        print(path)
        break
else:
    raise SystemExit("signed manifest contains no LPBC artifacts")
PY
) || fail "签名清单里没有可检查的 LPBC 文件"
CHECK_HOST=$(python3 - "$PROJECT_ROOT/license.dat" <<'PY'
import json
import sys

doc = json.load(open(sys.argv[1], encoding="utf-8"))
payload = doc.get("payload", {})
domains = payload.get("domains", [])
ips = payload.get("ipv4s", [])
print((domains or ips or [""])[0])
PY
)
PYTHONPATH="$AGENT_ROOT" "$AGENT_ROOT/venv/bin/python" -m app.agent.cli agent-check \
  --socket "$SOCKET_PATH" --host "$CHECK_HOST" --path "$ARTIFACT_REL" \
  --manifest "$PROJECT_ROOT/protected/lpbc/manifest.json" || fail "Agent 授权检查失败；确认域名/IP 与 License 一致"
"$PHP_BIN" -m | grep -qi '^license_loader$' || fail "CLI PHP 未加载 license_loader"

printf '\n安装完成。Agent 路径：%s\n项目路径（未更改）：%s\n' "$AGENT_ROOT" "$PROJECT_ROOT"
printf 'Hyperf 是常驻 CLI 进程：请在宝塔中重启此项目对应的守护任务，使其加载新 Loader。仅 reload PHP-FPM 不会更新 Hyperf。\n'
if [[ -n "$PHP_FPM_SERVICE" ]]; then
  printf 'PHP-FPM 服务：%s（%s）\n' "$PHP_FPM_SERVICE" "$FPM_ACTION"
else
  printf '未自动识别 PHP-FPM 服务；Agent 与 CLI Loader 已验证。请检查宝塔对应 PHP-FPM 是否加载 %s/license_loader.ini\n' "${SCAN_DIR:-$(dirname "$PHP_INI")}" 
fi
