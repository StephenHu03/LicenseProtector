LicenseProtector Windows 加密工具

用途：在厂商 Windows 电脑选择 PHP 文件、签发授权并生成交付内容。

新版程序：
  安装包\LicenseProtector-Windows-Encryptor.exe

程序源码快照：
  源码\LicenseProtector-Windows-Source\

三步操作：
  1. 选择项目：保留你的本机项目路径，选择 PHP 文件或目录，在文件预览里确认范围。
  2. 配置授权：输入域名或 IPv4，点击添加或按回车；选择最低 PHP 和产品版本。
  3. 生成交付：核对范围与授权，填写独立的输出目录，点击生成交付包。

默认使用 Native Loader 加密包。标准授权包只做授权和选中文件的注释/空白处理。
打包期间配置会锁定，完成后可以直接打开交付目录。Ctrl+Enter 可触发生成。
安装版为 安装包\LicenseProtector-Windows加密工具-Setup.exe。
源码更新不会自动更新已经安装的旧程序，请使用本次重建的 EXE 或重新安装。

Native Loader 模式会同时生成 PHP 加密交付目录和项目专属 Linux 安装 ZIP。
厂商身份首次使用时自动初始化，之后会复用：
  %LOCALAPPDATA%\LicenseProtector\keys\vendor_private.pem
  %LOCALAPPDATA%\LicenseProtector\keys\vendor_public.pem

vendor_private.pem 只留在本机，绝不能上传服务器。Linux 安装 ZIP 包含项目
runtime.key，必须经可信渠道传输；不要放在网站目录或提交到代码仓库。
