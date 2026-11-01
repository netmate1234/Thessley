# Thessley AD service -- one-line bootstrap
# Run from an elevated PowerShell:
#   irm https://wp-opsec.eagleeye-intelligence.com/wp-content/uploads/thessley-windows-downloads/ad-service-install.ps1 | iex
$ErrorActionPreference = 'Stop'
$zipUrl = 'https://wp-opsec.eagleeye-intelligence.com/wp-content/uploads/thessley-windows-downloads/thessley-ad-service-2026.11.01-7362b57-windows.zip'
$sha256 = '223c977143b8539660f74730f0bc43b90058731954ec94701ad35117247cec0d'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell window.'
}

$work = Join-Path $env:TEMP ('thessley-ad-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null
try {
    $zip = Join-Path $work 'thessley-ad-service.zip'
    Write-Host "Downloading $zipUrl"
    Invoke-WebRequest -Uri $zipUrl -OutFile $zip
    $actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $sha256) { throw "Checksum mismatch: expected $sha256, got $actual" }
    Write-Host 'Checksum verified.'
    Expand-Archive -Path $zip -DestinationPath $work -Force
    $installer = Get-ChildItem -Path $work -Recurse -Filter 'install-windows-service.ps1' |
        Select-Object -First 1
    if (-not $installer) { throw 'install-windows-service.ps1 was not found in the package.' }
    Write-Host "Running $($installer.FullName)"
    & $installer.FullName
} finally {
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
