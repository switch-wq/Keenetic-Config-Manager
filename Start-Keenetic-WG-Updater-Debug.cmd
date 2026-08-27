@echo off
cd /d "%~dp0"
echo === Keenetic WG Updater v1.3.2 DEBUG ===
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Keenetic-WG-Updater.ps1"
echo.
echo Exit code: %ERRORLEVEL%
echo Press any key to close...
pause >nul
