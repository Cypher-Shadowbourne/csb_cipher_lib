# run_workflow.ps1

# Check if act is installed
if (-not (Get-Command act -ErrorAction SilentlyContinue)) {
    Write-Host "act is not installed. Please install act via Chocolatey:"
    Write-Host "choco install act-cli"
    exit 1
}

# Run the default GitHub Actions workflow (simulate a push event)
act
