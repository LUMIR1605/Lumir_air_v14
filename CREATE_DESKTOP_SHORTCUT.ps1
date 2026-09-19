$ErrorActionPreference = "Stop"

$launcher = Get-Item -LiteralPath (Join-Path $PSScriptRoot "LUMIR_OSINT_LAB.cmd")
$desktop = [Environment]::GetFolderPath("Desktop")
if ([string]::IsNullOrWhiteSpace($desktop)) {
    throw "Nie mozna ustalic sciezki pulpitu Windows."
}

$shortcutPath = Join-Path $desktop "LUMIR OSINT LAB.lnk"
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $launcher.FullName
$shortcut.WorkingDirectory = $PSScriptRoot
$shortcut.Description = "LUMIR OSINT LAB - prywatna analiza lokalna"
$shortcut.WindowStyle = 7
$shortcut.Save()

if (-not (Test-Path -LiteralPath $shortcutPath -PathType Leaf)) {
    throw "Nie udalo sie utworzyc skrotu na pulpicie."
}

Write-Host "Utworzono skrot: $shortcutPath"
