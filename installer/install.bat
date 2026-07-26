@echo off
:: SQL Server Performance Dashboard — one-click installer wrapper
:: Runs install.ps1 in a bypassed execution policy. No admin required.
setlocal

echo.
echo Starting SQL Dashboard installer...
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*

echo.
if errorlevel 1 (
    echo Install failed. Check the messages above.
    pause
    exit /b 1
) else (
    echo.
    pause
)
