@echo off
rem Thin wrapper so "vpn-chain start" works from cmd.exe / PowerShell / Run dialog.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0vpn-chain.ps1" %*
exit /b %ERRORLEVEL%
