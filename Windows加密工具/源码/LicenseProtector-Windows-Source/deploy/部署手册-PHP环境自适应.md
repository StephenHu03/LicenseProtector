# LicenseProtector Linux 部署手册（PHP 环境自适应）

这份手册用于把当前服务器的真实环境转换成一份可检查、可重复执行的安装命令。它会识别：

- PHP 项目目录
- 运行该项目的 PHP CLI、`phpize`、`php-config`
- Nginx 站点和 Hyperf upstream 端口
- 对应的 PHP-FPM systemd 服务

它不会移动或改名 PHP 项目，不会删除 `/etc/license-protector` 中已有的密钥，也不会结束未知的 PHP 进程。

## 一、前置条件

1. Windows 端已经生成该项目对应的 PHP 加密交付目录和 Linux 部署包。
2. PHP 加密交付内容已经复制到服务器原有项目目录，例如：

   ```text
   /www/wwwroot/zixishiapi.liantigou.com/BackEnd
   ```

3. Linux 部署包已经上传并解压。例如解压目录为：

   ```text
   /root/LicenseProtector-Linux-Installer
   ```

4. 使用 root 或具备 `sudo` 权限的账号操作。

部署包只能通过可信渠道传输，不能放在网站 `root` 目录、Git 仓库或公开下载目录。

## 二、生成本机专用安装命令

以下代码只做检测和生成，不安装、不重启服务。请在宝塔终端中整段粘贴，不要复制终端提示符 `[root@...]#`。

如果部署包路径不同，只修改第一行 `PACKAGE_ROOT`；如果 Nginx 配置中有多个站点，填写实际域名。

```bash
set -Eeuo pipefail

PACKAGE_ROOT="/root/LicenseProtector-Linux-Installer"
SITE_DOMAIN="zixishiapi.liantigou.com"
PROJECT_ROOT="/www/wwwroot/zixishiapi.liantigou.com/BackEnd"
OUT="/root/licenseprotector-detected"
# 已确认本台服务器后端使用 PHP 8.2。其他服务器请填实际路径；留空仅从项目进程检测。
PHP_BIN="/www/server/php/82/bin/php"

die() { printf '检测失败：%s\n' "$*" >&2; exit 1; }
[[ -d "$PACKAGE_ROOT" ]] || die "部署包目录不存在：$PACKAGE_ROOT"
[[ -d "$PROJECT_ROOT" ]] || die "PHP 项目目录不存在：$PROJECT_ROOT"
[[ -f "$PROJECT_ROOT/license.dat" ]] || die "项目缺少 license.dat：$PROJECT_ROOT"
[[ -f "$PROJECT_ROOT/protected/lpbc/manifest.json" ]] || die "项目缺少 protected/lpbc/manifest.json"
[[ -f "$PROJECT_ROOT/protected/lpbc/manifest.sig" ]] || die "项目缺少 protected/lpbc/manifest.sig"
[[ -f "$PACKAGE_ROOT/install.sh" ]] || die "部署包缺少 install.sh：$PACKAGE_ROOT"

realpath_safe() { readlink -f "$1" 2>/dev/null || true; }

# 优先从项目目录下正在运行的 Hyperf/PHP 进程识别 PHP，避免选到其他站点的 PHP。
if [[ -z "$PHP_BIN" ]]; then
for d in /proc/[0-9]*; do
  p=${d##*/}
  [[ -r "$d/cwd" && -r "$d/exe" ]] || continue
  cwd=$(realpath_safe "$d/cwd")
  [[ "$cwd" == "$PROJECT_ROOT" ]] || continue
  exe=$(realpath_safe "$d/exe")
  case "$exe" in
    */php) PHP_BIN="$exe"; break ;;
  esac
done
fi

# 没有项目进程时禁止猜测其他站点的 PHP，避免选错版本。
[[ -x "$PHP_BIN" ]] || die "没有找到 PHP；请在脚本中手动填写 PHP_BIN"

PHP_DIR=$(dirname "$PHP_BIN")
PHPIZE="$PHP_DIR/phpize"
PHP_CONFIG="$PHP_DIR/php-config"
[[ -x "$PHPIZE" ]] || die "缺少匹配的 phpize：$PHPIZE"
[[ -x "$PHP_CONFIG" ]] || die "缺少匹配的 php-config：$PHP_CONFIG"

PHP_VERSION=$($PHP_BIN -r 'echo PHP_MAJOR_VERSION,".",PHP_MINOR_VERSION,".",PHP_RELEASE_VERSION;')
PHP_CONFIG_VERSION=$($PHP_CONFIG --version)
PHP_API=$($PHPIZE -v | awk -F': ' '/PHP Api Version/ {print $2; exit}')
PHP_EXTENSION_DIR=$($PHP_CONFIG --extension-dir)
[[ "$PHP_CONFIG_VERSION" == "$PHP_VERSION"* ]] || die "PHP 与 php-config 不匹配：$PHP_VERSION / $PHP_CONFIG_VERSION"
[[ -n "$PHP_API" ]] || die "无法读取 PHP API 版本"

FPM_BIN="$PHP_DIR/php-fpm"
[[ -x "$FPM_BIN" ]] || FPM_BIN="$(dirname "$PHP_DIR")/sbin/php-fpm"
[[ -x "$FPM_BIN" ]] || die "缺少匹配的 php-fpm：$FPM_BIN"
FPM_INI=$("$FPM_BIN" -i 2>/dev/null | sed -n 's/^Loaded Configuration File => //p' | head -n 1)
[[ -n "$FPM_INI" && -f "$FPM_INI" ]] || die "无法定位 PHP-FPM 配置文件"

NGINX_CONF="/www/server/panel/vhost/nginx/${SITE_DOMAIN}.conf"
UPSTREAM_PORT=""
if [[ -f "$NGINX_CONF" ]]; then
  UPSTREAM_PORT=$(awk '/^[[:space:]]*server[[:space:]]+127\.0\.0\.1:[0-9]+/ {sub(/.*:/,"",$2); sub(/;.*/,"",$2); print $2; exit}' "$NGINX_CONF")
fi

# 若站点没有独立配置文件，仍从 Nginx 完整配置中查找该域名附近的 upstream。
if [[ -z "$UPSTREAM_PORT" && -x "$(command -v nginx 2>/dev/null || true)" ]]; then
  NGINX_DUMP=$(nginx -T 2>/dev/null || true)
  UPSTREAM_PORT=$(printf '%s\n' "$NGINX_DUMP" | awk -v d="$SITE_DOMAIN" '
    $0 ~ "server_name[[:space:]]+" d ";" {inside=1}
    inside && $1 == "proxy_pass" && $2 ~ /127\\.0\\.0\\.1:[0-9]+/ {x=$2; sub(/.*:/,"",x); sub(/;.*/,"",x); print x; exit}
    inside && /^}/ {inside=0}
  ')
fi

FPM_SERVICE=""
compact=${PHP_VERSION%.*}; compact=${compact/./}
for service in "php-fpm-$compact" "php${compact}-fpm" php-fpm; do
  if systemctl cat "$service" >/dev/null 2>&1; then FPM_SERVICE="$service"; break; fi
done
[[ -n "$FPM_SERVICE" ]] || FPM_SERVICE="手动填写"

mkdir -p "$OUT"
cat > "$OUT/variables.env" <<EOF
PACKAGE_ROOT=$(printf '%q' "$PACKAGE_ROOT")
SITE_DOMAIN=$(printf '%q' "$SITE_DOMAIN")
PROJECT_ROOT=$(printf '%q' "$PROJECT_ROOT")
PHP_BIN=$(printf '%q' "$PHP_BIN")
PHPIZE=$(printf '%q' "$PHPIZE")
PHP_CONFIG=$(printf '%q' "$PHP_CONFIG")
PHP_VERSION=$(printf '%q' "$PHP_VERSION")
PHP_API=$(printf '%q' "$PHP_API")
PHP_EXTENSION_DIR=$(printf '%q' "$PHP_EXTENSION_DIR")
FPM_BIN=$(printf '%q' "$FPM_BIN")
FPM_INI=$(printf '%q' "$FPM_INI")
UPSTREAM_PORT=$(printf '%q' "${UPSTREAM_PORT:-未检测到}")
FPM_SERVICE=$(printf '%q' "$FPM_SERVICE")
EOF

cat > "$OUT/install-generated.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/variables.env"
die() { printf '安装停止：%s\n' "$*" >&2; exit 1; }

[[ "$FPM_SERVICE" != "手动填写" ]] || die "variables.env 中的 FPM_SERVICE 需要手动填写"
[[ -x "$PHP_BIN" && -x "$PHPIZE" && -x "$PHP_CONFIG" ]] || die "PHP 工具路径不可执行"
[[ -x "$FPM_BIN" && -f "$FPM_INI" ]] || die "PHP-FPM 路径或配置文件不可用"
[[ -d "$PROJECT_ROOT" ]] || die "项目目录不存在：$PROJECT_ROOT"

printf '将使用以下参数：\n'
printf '  项目：%s\n  PHP：%s (%s)\n  API：%s\n  FPM：%s\n  upstream：%s\n' \
  "$PROJECT_ROOT" "$PHP_BIN" "$PHP_VERSION" "$PHP_API" "$FPM_SERVICE" "$UPSTREAM_PORT"
printf '  FPM 配置：%s\n' "$FPM_INI"
printf '\n确认以上路径都正确后按回车继续，输入 n 取消：'
read -r answer
[[ -z "$answer" || "$answer" == y || "$answer" == Y ]] || die "用户取消"

# 旧版本可能留下 PHP 8.1 的 configure/Makefile；仅清理部署包内 Loader 的生成物。
cd "$PACKAGE_ROOT/native/loader" || die "Loader 源码目录不存在"
"$PHPIZE" --clean >/dev/null 2>&1 || true
rm -f configure config.h config.status Makefile Makefile.objects \
  libtool config.nice modules/license_loader.so

# 安装器编译和自检后配置 CLI/FPM ini，并为修改的 ini 保留备份。
cd "$PACKAGE_ROOT" || exit 1
PHPIZE="$PHPIZE" PHP_CONFIG="$PHP_CONFIG" PATH="$(dirname "$PHP_BIN"):$PATH" \
  bash ./install.sh \
  --project-root "$PROJECT_ROOT" \
  --php "$PHP_BIN" \
  --php-fpm-service "$FPM_SERVICE"
SCRIPT
chmod 700 "$OUT/install-generated.sh"

printf '\n检测完成，结果已写入：\n'
cat "$OUT/variables.env"
printf '\n下一步先审阅并执行：\n  less %q\n  bash %q\n' "$OUT/variables.env" "$OUT/install-generated.sh"
```

## 三、执行前必须核对

先查看生成结果：

```bash
cat /root/licenseprotector-detected/variables.env
```

在目前这台服务器上，预期应接近以下值：

```text
PROJECT_ROOT=/www/wwwroot/zixishiapi.liantigou.com/BackEnd
PHP_BIN=/www/server/php/82/bin/php
PHP_VERSION=8.2.x
PHP_API=20220829
UPSTREAM_PORT=9501
FPM_SERVICE=php-fpm-82
```

如果 `PROJECT_ROOT`、`PHP_BIN`、`UPSTREAM_PORT` 或 `FPM_SERVICE` 不对，先修改生成器顶部的变量并重新运行检测。不要用其他项目的 PHP 或端口替换它们。

## 四、执行安装

确认参数正确后执行：

```bash
bash /root/licenseprotector-detected/install-generated.sh
```

脚本会在部署包自己的 `native/loader` 目录中清理旧的编译产物，再使用检测到的 PHP 版本重新编译 Loader。它不会清理项目目录，也不会覆盖不同的运行密钥。遇到“已有不同运行密钥”时应停止，不要删除密钥硬装。

## 五、安装结果验证

安装成功后，先验证 CLI：

```bash
source /root/licenseprotector-detected/variables.env
"$PHP_BIN" -r 'printf("PHP=%s extension=%s function=%s\n", PHP_VERSION, extension_loaded("license_loader") ? "yes" : "no", function_exists("lpbc_execute") ? "yes" : "no");'
"$PHP_BIN" -m | grep -i '^license_loader$'
systemctl is-active license-agent
```

预期必须同时满足：

```text
extension=yes function=yes
active
```

然后确认实际后端仍监听 Nginx 配置中的端口：

```bash
ss -lntp | grep ":${UPSTREAM_PORT}"
```

## 六、PHP-FPM 重启失败时怎么处理

安装器可能已经完成 Agent 和 Loader 安装，但最后重启 FPM 失败。此时不要重复安装、不要 `kill -9` Hyperf、不要删除密钥。先保存诊断输出：

```bash
source /root/licenseprotector-detected/variables.env
systemctl status "$FPM_SERVICE" --no-pager -l
journalctl -u "$FPM_SERVICE" -n 100 --no-pager
"$PHP_BIN" --ini
"$PHP_BIN" -m 2>&1 | grep -i -C2 'license_loader\|warning\|error' || true
```

常见原因是 FPM 与 CLI 不是同一套 PHP 配置，或 FPM 配置中出现重复的 `extension=license_loader.so`。确认日志后再处理配置；不要把 PHP 8.1 的 `.so` 复制给 PHP 8.2。Loader 必须满足：

```text
PHP 8.2 -> API 20220829
PHP 8.1 -> API 20210902
```

## 七、回到接口验证

CLI Loader、Agent 验证成功后，还必须在宝塔中重启这个项目对应的 Hyperf 守护任务，让常驻进程加载新扩展。仅 reload PHP-FPM 不会更新 Hyperf。不要重启其他项目的任务，也不要按搜索到的第一个 PHP PID 结束进程。然后再从 Postman 请求接口。若仍返回 500，同时查看 Hyperf 的实际日志：

```bash
cd /www/wwwroot/zixishiapi.liantigou.com/BackEnd
find runtime logs -type f -mmin -10 -print 2>/dev/null
```

如果日志仍写着 `native Loader extension is not loaded`，说明请求进程没有使用 `variables.env` 中的 PHP，或 Hyperf 进程没有按正确方式重启；把以下三项发回即可继续定位：

```bash
source /root/licenseprotector-detected/variables.env
for process_dir in /proc/[0-9]*; do
  [[ "$(readlink -f "$process_dir/cwd" 2>/dev/null)" == "$PROJECT_ROOT" ]] || continue
  printf 'PID=%s PHP=%s 目录=%s\n' "${process_dir##*/}" \
    "$(readlink -f "$process_dir/exe" 2>/dev/null)" "$PROJECT_ROOT"
done
"$PHP_BIN" -r 'var_export([PHP_VERSION, extension_loaded("license_loader"), function_exists("lpbc_execute")]); echo PHP_EOL;'
```
