@echo off
rem Berayan launcher - double-click this file or run "berayan" in cmd / PowerShell (".\berayan.cmd").
title Berayan
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0berayan.ps1" %*
exit /b %ERRORLEVEL%
