@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel% equ 0 (
    py -3 lumir_shield_app.py
) else (
    where python >nul 2>nul
    if %errorlevel% equ 0 (
        python lumir_shield_app.py
    ) else (
        echo Python nie jest zainstalowany lub nie jest dostepny w PATH.
        pause
    )
)
endlocal
