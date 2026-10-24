@echo off
REM Mewtwo launcher — double-click this to start the dashboard.
REM Uses the project's virtual-env directly, no activation needed.
cd /d "%~dp0.."
if exist ".venv\Scripts\mewtwo.exe" (
    ".venv\Scripts\mewtwo.exe" serve
) else (
    echo .venv not found - falling back to system Python.
    python -m mewtwo serve
)
pause
