@echo off
setlocal

powershell -ExecutionPolicy ByPass -NoProfile -file ./build.ps1
exit /b %ERRORLEVEL%