param()

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $root ".venv\Scripts\python.exe"
$iss = Join-Path $root "installer\LumirShield.iss"
$isccCandidates = @(
    (Join-Path $root ".tools\Inno Setup Portable\ISCC.exe"),
    (Join-Path $root ".tools\Inno Setup\ISCC.exe"),
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 7\ISCC.exe"
)

if (!(Test-Path -LiteralPath $python)) { throw "Brakuje .venv. Utwórz środowisko programistyczne przed budową." }
& $python -m pytest -q --basetemp (Join-Path $root ".pytest-build") -p no:cacheprovider
if ($LASTEXITCODE -ne 0) { throw "Testy nie przeszły; budowa przerwana." }
& $python -m PyInstaller --noconfirm --clean --onefile --windowed --name LumirShield --add-data "templates;templates" --add-data "config;config" --collect-all shield lumir_shield_app.py
if ($LASTEXITCODE -ne 0) { throw "Budowa EXE nie powiodła się." }

$iscc = $isccCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (!$iscc) { throw "Nie znaleziono Inno Setup Compiler (ISCC.exe)." }
& $iscc $iss
if ($LASTEXITCODE -ne 0) { throw "Budowa instalatora nie powiodła się." }
Write-Host "Gotowe: $(Join-Path $root 'dist\LumirShield.exe')"
Write-Host "Gotowe: $(Join-Path $root 'release\LumirShield-Setup-RC6.exe')"
