param(
    [Parameter(Mandatory = $true)]
    [string]$ChangeDir
)
 
$python = Get-Command python3 -ErrorAction SilentlyContinue
if ($null -eq $python) {
    $python = Get-Command python -ErrorAction SilentlyContinue
}
if ($null -eq $python) {
    Write-Error "python3 or python is required to run the AR traceability validator"
    exit 1
}
 
$validator = Join-Path $PSScriptRoot "validate_change.py"
& $python.Source $validator --change-dir $ChangeDir
exit $LASTEXITCODE