param([string]$ConfigPath)
$ErrorActionPreference = 'Stop'
$source = Split-Path -Parent $PSScriptRoot
$target = Join-Path $env:USERPROFILE '.h2a'
if (Test-Path -LiteralPath $target) {
  if ((Get-Item -LiteralPath $target).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Destino é um link; operação interrompida.' }
  if (@(Get-ChildItem -LiteralPath $target -Force).Count) { throw 'Instalação existente; use a desinstalação para arquivar antes de reinstalar.' }
}
if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw 'Instale Node.js 22 ou superior.' }
$major = [int]((& node --version) -replace '^v(\d+).*', '$1')
if ($major -lt 22) { throw 'Node.js 22 ou superior necessário.' }
$config = @{ endpoint = $null; publicKey = $null; identity = 'local-agent' }
if ($ConfigPath) {
  # This file must contain public settings only. Credentials stay in the process environment.
  $candidate = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
  $allowed = @('endpoint', 'publicKey', 'identity')
  if (@($candidate.PSObject.Properties.Name | Where-Object { $_ -notin $allowed }).Count) { throw 'Configuração contém campos não permitidos.' }
  $config = @{ endpoint = $candidate.endpoint; publicKey = $candidate.publicKey; identity = $candidate.identity }
}
New-Item -ItemType Directory -Path (Join-Path $target 'src') | Out-Null
Copy-Item -LiteralPath (Join-Path $source 'src/cli.mjs'),(Join-Path $source 'src/client.mjs'),(Join-Path $source 'src/protocol.mjs') -Destination (Join-Path $target 'src')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'uninstall.ps1') -Destination $target
$config | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $target 'config.json') -Encoding utf8
@'
@echo off
node "%~dp0src\cli.mjs" %*
exit /b %errorlevel%
'@ | Set-Content -LiteralPath (Join-Path $target 'a2h.cmd') -Encoding ascii
# Restrict local configuration and executable replacement to this user and SYSTEM.
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $target /inheritance:r /grant:r "*${sid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' /Q | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Não foi possível restringir permissões da instalação.' }
Write-Output 'Instalado em %USERPROFILE%\.h2a. Configure endpoint/chave pública/identidade e injete A2H_API_KEY no ambiente do processo.'
