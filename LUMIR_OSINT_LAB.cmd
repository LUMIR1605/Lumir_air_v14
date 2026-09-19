@echo off
setlocal
set "LUMIR_REPO=%~dp0"
cd /d "%LUMIR_REPO%"
if errorlevel 1 (
  echo [LUMIR OSINT LAB] Nie mozna otworzyc katalogu aplikacji.
  pause
  exit /b 1
)

where python >nul 2>&1
if errorlevel 1 (
  echo [LUMIR OSINT LAB] Nie znaleziono programu Python w PATH.
  pause
  exit /b 1
)

python -c "import tkinter; import osint_lab.desktop_gui" >nul 2>&1
if errorlevel 1 (
  echo [LUMIR OSINT LAB] Brakuje tkinter lub zaleznosci projektu.
  echo Uruchom: python -m pytest -q
  pause
  exit /b 1
)

python -m osint_lab.desktop_gui
if errorlevel 1 (
  echo [LUMIR OSINT LAB] Aplikacja zakonczyla dzialanie z bledem.
  pause
  exit /b 1
)
endlocal
