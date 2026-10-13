# LicenseProtector

离线 PHP 源码授权保护工具（V1）。

开发者：**Stephen Hu**（stephenhu031028@gmail.com）。

工具只修改临时复制的项目，业务源码仍可编辑；交付包使用 Ed25519 签名 License、多个域名或多个服务器 IPv4 的任一匹配校验，以及由同一厂商私钥签名的保护文件完整性清单，并且运行时不访问网络。

Hyperf 项目会额外生成授权中间件，在每个 HTTP 请求中校验真实 Host；不会在 Hyperf 的 CLI 启动阶段误判域名。

## CLI

```powershell
& .\.venv\Scripts\python.exe -m app.cli keygen --private keys\vendor_private.pem --public keys\vendor_public.pem
& .\.venv\Scripts\python.exe -m app.cli build --project D:\Project\Backend --domain customer.example.com --domain api.customer.example.com --ipv4 123.123.123.123 --php-min-version 8.1 --version 1.0.0 --private-key keys\vendor_private.pem --public-key keys\vendor_public.pem --output dist
```

私钥仅保存在厂商电脑，绝不能放进客户交付包或代码仓库。

注意：`LicenseProtector-Windows加密工具-Setup.exe` 是厂商签发工具，不要把它发给客户。Native 模式的客户需要 PHP 加密目录及对应 Linux 安装 ZIP。标准授权包不需要 Native Loader。厂商私钥不会进入交付包。

每次打包结果自动归档到：

```text
<输出目录>/history/<UTC时间戳>_<LicenseID>/
├── <项目名>_Release_<版本>/
└── <项目名>_Release_<版本>.zip
```

Windows 安装程序放在 `Windows加密工具/安装包`，Linux 通用源码部署包放在 `Linux授权服务端/安装包`。Native 模式生成 PHP 加密交付目录的同时，会在所选输出目录旁生成一个项目专属 Linux 安装 ZIP；该 ZIP 包含项目运行密钥，因此不要把它提交仓库、放到网站目录或公开发送。

Windows 工具自动在用户数据目录初始化并复用厂商身份：

```text
%LOCALAPPDATA%\LicenseProtector\keys\vendor_private.pem
%LOCALAPPDATA%\LicenseProtector\keys\vendor_public.pem
```

私钥只用于 Windows 签发，不能上传服务器；公钥和项目专属运行密钥会自动放入 Linux 项目安装 ZIP。项目运行密钥按项目路径自动创建并复用，无需在界面手工浏览选择。首次打包会自动初始化厂商身份，也可在第二步点击“检查 / 初始化身份”提前生成；覆盖密钥不会被自动执行。

Windows 界面分成三步：选择项目、配置授权、生成交付。默认使用 Native Loader 加密包。文件预览支持逐个移除；域名/IP 支持回车添加和自动提交未添加输入。生成时锁定配置，完成后可直接打开交付目录。Linux ZIP 内附环境自适应部署手册，安装后需重启此项目对应的 Hyperf 常驻任务。

当前运行环境固定为 PHP + Hyperf。授权支持多个域名和多个 IPv4，任意一个匹配即可通过。目标服务器 PHP 版本在打包时选择（默认 PHP 8.1+），并要求启用 sodium 扩展；详细流程和运行时校验原理见 `docs/打包原理说明.md`。

## 免费源代码加固

图形界面项目区可选择单个 PHP 文件或整个目录。仅选中的文件会在临时交付副本中移除普通注释和冗余空白，再纳入签名完整性清单；原项目不会被修改。文档注释会保留，以兼容可能依赖注释的 Hyperf 项目。

命令行可重复指定文件或目录：

```powershell
& .\.venv\Scripts\python.exe -m app.cli build --project D:\Project\Backend --domain customer.example.com --version 1.0.0 --private-key keys\vendor_private.pem --public-key keys\vendor_public.pem --output dist --harden-file app\Service\Billing.php --harden-dir app\Domain --php-executable php
```

这是免费混淆加固，不是加密：服务器无需安装解密器或 Loader。

## 自研 LPBC Loader

当前仓库提供自研 LPBC/Agent/PHP 扩展实现，不依赖 ionCube。Windows Native 打包流程会同时产出 PHP 交付目录和项目专属 Linux 安装 ZIP：

```powershell
& .\.venv\Scripts\python.exe -m app.cli agent-keygen --output C:\Secrets\license-agent\runtime.key
& .\.venv\Scripts\python.exe -m app.cli encode --project D:\Project\Backend --private-key keys\vendor_private.pem --output D:\Encoded --runtime-key C:\Secrets\license-agent\runtime.key --domain customer.example.com --version 1.0.0 --file app\Service\Payment.php
```

命令行 `encode` / `native-build` 仍保留供高级使用；日常 GUI 会自动管理密钥。Native 模式生成的 Linux 安装 ZIP 含该项目的运行密钥，应通过可信渠道传输，并在服务器上限制访问。

要保护普通 PHP/Hyperf 文件，使用 `native-build`。它会把选中的源文件放入 LPBC，并在原路径写入 Loader shim；运行时由 PHP 扩展在内存中调用 Zend 编译器执行，源文件不会写回磁盘：

```powershell
& .\.venv\Scripts\python.exe -m app.cli native-build --project D:\Project\Backend --output D:\Delivery --runtime-key C:\Secrets\license-agent\runtime.key --private-key keys\vendor_private.pem --domain customer.example.com --version 1.0.0 --dir app\Service
```

完整 PHP native-build 使用 `php-source-v1`，由目标 PHP ABI 的 Loader 在内存中调用 Zend 编译器执行，因此支持普通类、方法、属性、Composer 和 Hyperf 代码。扩展必须在目标 Linux/PHP ABI 上编译测试后才能部署；本 Windows 开发环境没有 Linux PHP 头文件和 C 工具链，因此此处尚不能声称原生扩展已经通过编译。协议细节见 `docs/自研Loader协议.md` 和 `native/README.md`。

将 PHP 交付内容覆盖到原 PHP 项目目录（不更改路径），解压项目专属 Linux ZIP 后执行：

```sh
sudo bash ./install.sh --project-root /你的/原PHP项目路径
```

安装器将 Agent 固定部署在 `/opt/license-protector-agent`，密钥和配置放入 `/etc/license-protector`，Socket 位于 `/run/license-protector/agent.sock`，并在目标服务器按检测到的 PHP ABI 编译 Loader。PHP 开发头文件及 libsodium 开发库必须可用；缺少依赖时安装器会报错停止，不会修改 PHP 项目路径。
