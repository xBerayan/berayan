@echo off
rem TunnelStack launcher - double-click this file or run "tunnelstack" in cmd / PowerShell (".\tunnelstack.cmd").
title TunnelStack
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\tunnelstack.ps1" %*
exit /b %ERRORLEVEL%
