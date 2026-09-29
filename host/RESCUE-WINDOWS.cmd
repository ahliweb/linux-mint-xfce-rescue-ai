@echo off
rem Rescue host launcher for a RUNNING Windows 10/11. Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
rem Double-click this file. It only starts rescue-windows.ps1 from the rescue USB (read-only checks, no install,
rem no administrator rights, nothing written to this PC). Extra arguments are passed through, e.g. -EvidenceOnly.
setlocal
set "HERE=%~dp0"
set "PS1="
if exist "%HERE%rescue-omes\host\rescue-windows.ps1" set "PS1=%HERE%rescue-omes\host\rescue-windows.ps1"
if not defined PS1 if exist "%HERE%rescue-windows.ps1" set "PS1=%HERE%rescue-windows.ps1"
if not defined PS1 if exist "%HERE%..\rescue-windows.ps1" set "PS1=%HERE%..\rescue-windows.ps1"
set "RC=5"
if not defined PS1 goto :missing
set "PSEXE=powershell.exe"
if exist "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" set "PSEXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
"%PSEXE%" -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
set "RC=%ERRORLEVEL%"
goto :done
:missing
echo rescue-windows.ps1 tidak ditemukan / not found next to this launcher.
:done
echo.
echo Selesai (kode %RC%) / finished (code %RC%). Tekan tombol apa saja untuk menutup / press any key to close.
pause >nul
exit /b %RC%
