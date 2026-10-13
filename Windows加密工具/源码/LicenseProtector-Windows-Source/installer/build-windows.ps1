$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$workspaceRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $repoRoot))
$outputDir = Join-Path (Split-Path -Parent (Split-Path -Parent $repoRoot)) "安装包"
$workDir = Join-Path $repoRoot "final_build\windows_encryptor"
$python = Join-Path $workspaceRoot ".venv\Scripts\python.exe"
$appDataDir = Join-Path $workDir "data\app"

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "项目 Python 环境不存在：$python"
}
New-Item -ItemType Directory -Force -Path $outputDir, $workDir | Out-Null
if (Test-Path -LiteralPath $appDataDir) {
    $resolvedData = (Resolve-Path -LiteralPath $appDataDir).Path
    if (-not $resolvedData.StartsWith($workDir + "\", [StringComparison]::OrdinalIgnoreCase)) {
        throw "打包暂存目录超出构建目录：$resolvedData"
    }
    Remove-Item -LiteralPath $resolvedData -Recurse -Force
}
New-Item -ItemType Directory -Path $appDataDir | Out-Null
$appRoot = Join-Path $repoRoot "app"
Get-ChildItem -LiteralPath $appRoot -File -Recurse | ForEach-Object {
    $relative = $_.FullName.Substring($appRoot.Length + 1)
    if ($relative -match '(^|\\)__pycache__(\\|$)' -or $_.Extension -in @(".pyc", ".pyo")) { return }
    $destination = Join-Path $appDataDir $relative
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
    Copy-Item -LiteralPath $_.FullName -Destination $destination
}

Push-Location $repoRoot
try {
    & $python -m PyInstaller --noconfirm --clean --onefile --windowed `
        --name LicenseProtector-Windows-Encryptor `
        --distpath $outputDir --workpath $workDir --specpath $workDir `
        --add-data "$appDataDir;app" `
        --add-data "$repoRoot\deploy;deploy" `
        --add-data "$repoRoot\native;native" `
        --add-data "$repoRoot\LICENSE;." `
        --add-data "$repoRoot\pyproject.toml;." `
        --add-data "$repoRoot\requirements.txt;." `
        (Join-Path $repoRoot "app\main.py")
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller 构建失败，退出码 $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

$isccCandidates = @(
    (Get-Command ISCC.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1),
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) }
$isccCandidates = @($isccCandidates)
if ($isccCandidates.Count -eq 0) {
    throw "Windows EXE 已生成；未找到 Inno Setup 6，Setup.exe 未更新。请安装 Inno Setup 6 后重新构建。"
}

& $isccCandidates[0] "/DPackageDir=$outputDir" (Join-Path $PSScriptRoot "LicenseProtector.iss")
if ($LASTEXITCODE -ne 0) {
    throw "Inno Setup 构建失败，退出码 $LASTEXITCODE"
}
