# LicenseProtector Linux 安装命令

只需要定义 `PHP_VERSION` 这个变量，再将**整个代码块**复制到服务器终端执行。比如服务器用 PHP 8.1，就把 `PHP_VERSION='8.2'` 改为 `PHP_VERSION='8.1'`；命令会自动选择 `/www/server/php/81/bin/php`、`phpize` 和 `php-config`。PHP 8.2 对应目录 `82`，其他版本同理。其余路径仅在你的服务器实际路径不同时才修改。

## 填写参数

- `PHP_VERSION`：后端实际使用的 PHP 版本，支持 `8.2` 或 `82`，也支持其他主、次版本。
- `PHP_BASE_DIR`：宝塔 PHP 安装目录，默认 `/www/server/php`。
- `INSTALLER_DIR`：已经解压的服务端安装目录，不需要压缩包。
- `PROJECT_ROOT`：现有后端项目目录，不会移动或改名。
- `PHP_USER`、`PHP_GROUP`：有权连接 Agent 的 PHP 运行用户和组，宝塔通常为 `www`。

当前这个后端曾报告 Composer 依赖要求 PHP >= 8.2；如果部署的仍是该版本代码，请填写至少 `8.2`。安装器会检查版本和开发工具，但不负责升级 PHP 或安装系统构建依赖。

## 完整安装命令

```bash
/bin/bash <<'LICENSE_PROTECTOR_INSTALL'
set -Eeuo pipefail
trap 'echo "安装失败：行号=$LINENO，退出码=$?。请保留上面的错误输出。" >&2' ERR

# ===== 只修改这里 =====
PHP_VERSION='8.1' # 按后端实际版本修改，例如 8.1、8.2、8.3
PHP_BASE_DIR='/www/server/php'
INSTALLER_DIR='/root/LicenseProtector-Linux-Installer'
PROJECT_ROOT='/www/wwwroot/XX'
PHP_USER='www'
PHP_GROUP='www'
# ======================

fail() { echo "安装前检查失败：$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || fail '请在 root 终端执行'
[[ "$PHP_VERSION" =~ ^[0-9]+\.[0-9]+$ || "$PHP_VERSION" =~ ^[0-9]{2,}$ ]] \
  || fail 'PHP_VERSION 请填写主、次版本，例如 8.2 或 82，不要填补丁版本'

PHP_VERSION_COMPACT=${PHP_VERSION//./}
PHP_BIN_DIR="$PHP_BASE_DIR/$PHP_VERSION_COMPACT/bin"
PHP_BIN="$PHP_BIN_DIR/php"
PHPIZE_BIN="$PHP_BIN_DIR/phpize"
PHP_CONFIG_BIN="$PHP_BIN_DIR/php-config"

[[ -d "$INSTALLER_DIR" ]] || fail "安装目录不存在：$INSTALLER_DIR"
[[ -d "$PROJECT_ROOT" ]] || fail "项目目录不存在：$PROJECT_ROOT"
cd "$INSTALLER_DIR"

echo '== 修复安装脚本换行并检查 Bash 语法 =='
sed -i 's/\r$//' install.sh native/build-linux.sh
/bin/bash -n install.sh || fail 'install.sh 语法检查失败'
/bin/bash -n native/build-linux.sh || fail 'native/build-linux.sh 语法检查失败'

echo '== 检查安装文件和配套密钥 =='
for f in install.sh runtime.key vendor_public.pem native/build-linux.sh native/selfcheck.php; do
  [[ -s "$f" ]] || fail "缺少文件：$INSTALLER_DIR/$f"
done
for f in license.dat protected/lpbc/manifest.json protected/lpbc/manifest.sig; do
  [[ -s "$PROJECT_ROOT/$f" ]] || fail "项目缺少交付文件：$PROJECT_ROOT/$f"
done
getent passwd "$PHP_USER" >/dev/null || fail "用户不存在：$PHP_USER"
getent group "$PHP_GROUP" >/dev/null || fail "用户组不存在：$PHP_GROUP"

echo '== 检查目标 PHP 和开发工具 =='
for f in "$PHP_BIN" "$PHPIZE_BIN" "$PHP_CONFIG_BIN"; do
  [[ -x "$f" ]] || fail "工具不存在或不可执行：$f"
done
ACTUAL_VERSION=$("$PHP_BIN" -r 'echo PHP_MAJOR_VERSION,".",PHP_MINOR_VERSION;')
[[ "${ACTUAL_VERSION//./}" == "$PHP_VERSION_COMPACT" ]] \
  || fail "目录中的 PHP 实际版本为 $ACTUAL_VERSION，与填写的 $PHP_VERSION 不符"
CONFIG_VERSION=$("$PHP_CONFIG_BIN" --version)
[[ "${CONFIG_VERSION%.*}" == "$ACTUAL_VERSION" ]] \
  || fail "php-config 版本 $CONFIG_VERSION 与 PHP $ACTUAL_VERSION 不符"
printf 'PHP：%s（%s）\n项目：%s\n安装目录：%s\n' \
  "$ACTUAL_VERSION" "$PHP_BIN" "$PROJECT_ROOT" "$INSTALLER_DIR"

echo '== 安装 Agent，使用目标 PHP 重新编译 Loader =='
PHPIZE="$PHPIZE_BIN" \
PHP_CONFIG="$PHP_CONFIG_BIN" \
PATH="$PHP_BIN_DIR:$PATH" \
bash ./install.sh \
  --project-root "$PROJECT_ROOT" \
  --php "$PHP_BIN" \
  --php-user "$PHP_USER" \
  --php-group "$PHP_GROUP"

echo '== 验证安装结果 =='
systemctl is-active --quiet license-agent
[[ -S /run/license-protector/agent.sock ]] || fail 'Agent socket 尚未就绪'
"$PHP_BIN" "$INSTALLER_DIR/native/selfcheck.php"
systemctl status license-agent --no-pager -l

echo '安装及自检成功。'
echo "请在宝塔将此后端守护任务的 PHP 可执行文件设置为：$PHP_BIN"
echo "保留该任务原有参数，工作目录保持：$PROJECT_ROOT"
echo '然后重启此后端对应的守护任务，让常驻 Hyperf 进程加载新 Loader。'
LICENSE_PROTECTOR_INSTALL
```

## 文件要求与边界

安装目录中的 `runtime.key` 和 `vendor_public.pem` 必须与当前加密交付包配套。厂商私钥保留在 Windows 端，不上传服务器。

请使用包含 Loader 修复的安装源码。更改 PHP 版本会重新编译该版本的 Loader；旧 Hyperf 进程仍需要在宝塔中重启，安装成功不代表接口已经通过测试。

若报 `AbstractController::$request must not be accessed before initialization`，这是当前加密 shim 与 Hyperf 元数据扫描的兼容问题，重新安装不能修复。需要重新生成交付包，保留未加密的 `AbstractController.php`；带属性注入、注解、AOP 等扫描元数据的类也应暂时排除。

整段脚本由 `/bin/bash` 执行，不依赖宝塔终端当前的 Shell。复制时从 `/bin/bash <<'LICENSE_PROTECTOR_INSTALL'` 开始，到单独一行 `LICENSE_PROTECTOR_INSTALL` 结束。
