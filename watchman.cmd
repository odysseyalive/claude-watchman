@echo off
REM watchman.cmd — PATH shim for the claude-watchman Windows CLI. Resolves bin\watchman.ps1
REM relative to this file, so adding the repo root to PATH makes `watchman <verb>` work.
REM PRIME DIRECTIVE: this shim only forwards to the PowerShell CLI, which performs nothing
REM destructive itself (see bin\watchman.ps1).
setlocal
set "WATCHMAN_PS=%~dp0bin\watchman.ps1"
where pwsh >nul 2>nul
if %ERRORLEVEL%==0 (
  pwsh -NoProfile -File "%WATCHMAN_PS%" %*
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%WATCHMAN_PS%" %*
)
exit /b %ERRORLEVEL%
