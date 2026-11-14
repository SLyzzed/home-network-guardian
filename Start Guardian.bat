@echo off
setlocal
start "" /wait powershell.exe -NoLogo -NoProfile -STA -WindowStyle Hidden -File "%~dp0Guardian.ps1"
if errorlevel 1 (
  echo Guardian could not finish. If no message appeared, Windows may have blocked the script.
  echo Ask a trusted administrator for help. Do not disable organisational security policies.
  pause
)
