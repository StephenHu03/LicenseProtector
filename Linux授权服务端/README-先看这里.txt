LicenseProtector Linux 授权服务端

源码快照：
  源码\LicenseProtector-Linux-Agent\
  安装包\Linux授权服务端-源码部署包.zip

日常项目安装 ZIP 由 Windows Native 加密流程按项目生成，放在该次 PHP
加密交付目录的旁边。该项目 ZIP 含 runtime.key，不能公开或提交代码仓库。

先把 Windows 生成的 PHP 加密交付内容放到 PHP 项目原有路径，不要移动项目。
然后将项目 Linux 安装 ZIP 上传到服务器，解压。推荐先使用项目根目录中的
“部署手册-PHP环境自适应.md”生成本机专用命令；它会识别实际 PHP 版本、
phpize/php-config、Nginx upstream 和 PHP-FPM 服务，避免把 PHP 8.1 的 Loader
装到 PHP 8.2 项目上。

最简命令（已确认参数时使用）：

  sudo bash ./install.sh --project-root /你的/原PHP项目路径 --php /实际使用的PHP/bin/php

固定目录：
  /opt/license-protector-agent  Agent 与 Python 环境
  /etc/license-protector        运行密钥、公钥、Agent 配置
  /run/license-protector        PHP Loader 通信 Socket

安装器会在目标 Linux 服务器按实际 PHP 版本编译 Loader。PHP 开发头文件和
libsodium 开发库必须可用。CLI 和 PHP-FPM 可能读取不同的 ini；安装后必须分别
验证 CLI、FPM 和实际 Hyperf 进程。若 FPM 报 “Another FPM instance seems to
already listen”，先按部署手册检查宝塔已经运行的 master 进程，不要重复启动或
盲目 kill 进程。旧包保留在“旧版备份”，仅供回溯，不用于新部署。

Hyperf 是常驻 CLI 程序：安装 Loader 后，请在宝塔中重启该项目对应的守护任务。
只 reload PHP-FPM 无法让已启动的 Hyperf 进程加载新扩展。
新版通用包和项目专属 ZIP 内均包含“部署手册-PHP环境自适应.md”。
