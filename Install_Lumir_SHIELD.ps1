param(
    [string]$Source = (Join-Path $PSScriptRoot "LumirShield.exe")
)

$installDir = Join-Path $env:LOCALAPPDATA "Lumir SHIELD"
$desktop = [Environment]::GetFolderPath("Desktop")
if (!(Test-Path -LiteralPath $Source)) {
    Add-Type -AssemblyName PresentationFramework
    [System.Windows.MessageBox]::Show("Nie znaleziono LumirShield.exe. Najpierw uruchom build_windows_rc1.bat.", "Lumir SHIELD")
    exit 1
}
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
$destination = Join-Path $installDir "LumirShield.exe"
Copy-Item -LiteralPath $Source -Destination $destination -Force
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut((Join-Path $desktop "Lumir SHIELD.lnk"))
$shortcut.TargetPath = $destination
$shortcut.WorkingDirectory = $installDir
$shortcut.Description = "Lumir SHIELD - Security Intelligence Platform"
$shortcut.Save()
Add-Type -AssemblyName PresentationFramework
[System.Windows.MessageBox]::Show("Lumir SHIELD jest gotowy. Skrot utworzono na pulpicie.", "Lumir SHIELD")
