$ErrorActionPreference = 'Stop'
$target = [IO.Path]::GetFullPath((Join-Path $env:USERPROFILE '.h2a'))
$archive = Join-Path $env:USERPROFILE '.archive'
if (-not (Test-Path -LiteralPath $target)) { Write-Output 'A2H não está instalado.'; return }
if ((Get-Item -LiteralPath $target).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Instalação é um link; operação interrompida.' }
New-Item -ItemType Directory -Force -Path $archive | Out-Null
$destination = Join-Path $archive ('h2a-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N'))
Move-Item -LiteralPath $target -Destination $destination
Write-Output 'Instalação e configuração movidas para %USERPROFILE%\.archive; nenhum arquivo foi apagado.'
