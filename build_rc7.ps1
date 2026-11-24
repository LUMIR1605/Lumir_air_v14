param([string]$Python = "C:\Python314\python.exe")
$ErrorActionPreference="Stop"
Set-Location $PSScriptRoot
$out=Join-Path $PSScriptRoot "..\..\outputs\RC7"
& $Python -m PyInstaller --onefile --windowed --name LumirShield-RC7 --distpath $out --workpath ../build-rc7-release --specpath ../ --paths . --add-data "$PSScriptRoot\config\shield_sources.json;config" --collect-all shield lumir_shield_app.py
if($LASTEXITCODE -ne 0){throw "EXE build failed"}
& "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe" installer/LumirShield-RC7.iss
if($LASTEXITCODE -ne 0){throw "Installer build failed"}
