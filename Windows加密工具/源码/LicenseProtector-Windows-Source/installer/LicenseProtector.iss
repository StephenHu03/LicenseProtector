; LicenseProtector installer
; Developer: Stephen Hu <stephenhu031028@gmail.com>
#ifndef PackageDir
  #define PackageDir "..\..\..\安装包"
#endif
[Setup]
AppId={{B1E3D6C8-1F0D-4E0D-9E2C-5E0D1A5F2D11}
AppName=LicenseProtector Windows 加密工具
AppVersion=1.1.0
AppPublisher=Stephen Hu
AppPublisherURL=mailto:stephenhu031028@gmail.com
DefaultDirName={localappdata}\Programs\LicenseProtector Windows 加密工具
DisableDirPage=no
UsePreviousAppDir=yes
DefaultGroupName=LicenseProtector Windows 加密工具
OutputDir={#PackageDir}
OutputBaseFilename=LicenseProtector-Windows加密工具-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
UninstallDisplayName=LicenseProtector Windows 加密工具

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "快捷方式："

[Files]
Source: "{#PackageDir}\LicenseProtector-Windows-Encryptor.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Windows 加密工具"; Filename: "{app}\LicenseProtector-Windows-Encryptor.exe"
Name: "{autodesktop}\Windows 加密工具"; Filename: "{app}\LicenseProtector-Windows-Encryptor.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\LicenseProtector-Windows-Encryptor.exe"; Description: "启动 Windows 加密工具"; Flags: nowait postinstall skipifsilent
