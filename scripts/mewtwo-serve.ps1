# Mewtwo launcher (PowerShell). Run: .\scripts\mewtwo-serve.ps1
Set-Location (Join-Path $PSScriptRoot "..")
if (Test-Path ".venv\Scripts\mewtwo.exe") {
    & ".venv\Scripts\mewtwo.exe" serve
} else {
    Write-Host ".venv not found - falling back to system Python."
    python -m mewtwo serve
}
