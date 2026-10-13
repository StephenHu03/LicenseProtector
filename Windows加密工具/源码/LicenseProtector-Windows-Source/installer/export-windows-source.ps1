$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$sourceRoot = Split-Path -Parent $repoRoot
$archive = Join-Path $sourceRoot ("LicenseProtector-Windows-Source-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".zip")
if (Test-Path -LiteralPath $archive) {
    throw "源码包已存在，未覆盖：$archive"
}
$staging = Join-Path ([IO.Path]::GetTempPath()) ("LicenseProtector-source-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $staging | Out-Null

try {
    foreach ($name in @("app", "deploy", "docs", "installer", "native", "tests")) {
        $source = Join-Path $repoRoot $name
        Get-ChildItem -LiteralPath $source -File -Recurse | ForEach-Object {
            $relative = $_.FullName.Substring($repoRoot.Length + 1)
            if ($relative -match '(^|\\)(__pycache__|\.pytest_cache|\.source-staging|modules|\.libs|autom4te\.cache)(\\|$)' -or $_.Extension -in @(".pyc", ".pyo", ".o", ".lo", ".so")) { return }
            $destination = Join-Path $staging $relative
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
            Copy-Item -LiteralPath $_.FullName -Destination $destination
        }
    }
    foreach ($name in @("LICENSE", "README.md", "pyproject.toml", "requirements.txt")) {
        Copy-Item -LiteralPath (Join-Path $repoRoot $name) -Destination $staging
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory($staging, $archive)
} finally {
    $resolvedStaging = (Resolve-Path -LiteralPath $staging).Path
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $resolvedStaging.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or (Split-Path -Leaf $resolvedStaging) -notmatch '^LicenseProtector-source-[a-f0-9]{32}$') {
        throw "源码暂存目录校验失败，未删除：$resolvedStaging"
    }
    Remove-Item -LiteralPath $resolvedStaging -Recurse -Force
}

Write-Output "Windows 洁净源码包：$archive"
