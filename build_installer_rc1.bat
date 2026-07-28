@echo off
setlocal
powershell -ExecutionPolicy Bypass -File "%~dp0build_installer_rc1.ps1"
endlocal
