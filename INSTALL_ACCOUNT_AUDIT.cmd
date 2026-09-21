@echo off
setlocal EnableExtensions
set "ENV_DIR=%LOCALAPPDATA%\LumirOSINTLab\account_audit_env"
set "HOLEHE_VERSION=1.61"

echo LUMIR ACCOUNT AUDIT - optional local dependency installer
echo Target: %ENV_DIR%
echo This installs Holehe only inside the isolated virtual environment.

where py >nul 2>&1
if errorlevel 1 (
  echo FAIL: Python launcher ^(py.exe^) was not found.
  exit /b 1
)

set "PY_SPEC="
py -3.12 -c "import sys" >nul 2>&1 && set "PY_SPEC=-3.12"
if not defined PY_SPEC py -3.11 -c "import sys" >nul 2>&1 && set "PY_SPEC=-3.11"
if not defined PY_SPEC py -3.10 -c "import sys" >nul 2>&1 && set "PY_SPEC=-3.10"
if not defined PY_SPEC (
  echo FAIL: Install Python 3.10, 3.11 or 3.12, then run this helper again.
  echo The current Holehe 1.61 release is old and is not enabled blindly on newer interpreters.
  exit /b 1
)

if not exist "%ENV_DIR%\Scripts\python.exe" (
  echo Creating isolated environment with Python %PY_SPEC%...
  py %PY_SPEC% -m venv "%ENV_DIR%"
  if errorlevel 1 goto :fail
)

echo Installing pinned Holehe %HOLEHE_VERSION%...
"%ENV_DIR%\Scripts\python.exe" -m pip install --disable-pip-version-check "holehe==1.61"
if errorlevel 1 goto :fail

echo Verifying package, version and provider modules...
"%ENV_DIR%\Scripts\python.exe" "%~dp0osint_lab\account_audit\holehe_worker.py" --diagnose
if errorlevel 1 goto :fail
if not exist "%ENV_DIR%\Scripts\holehe.exe" (
  echo FAIL: Holehe CLI entry point was not created.
  exit /b 1
)

echo PASS: Account Audit dependency is installed in %ENV_DIR%
echo Restart LUMIR OSINT LAB to refresh diagnostics.
exit /b 0

:fail
echo FAIL: Account Audit dependency installation or verification failed.
exit /b 1
