param(
    [Parameter(Mandatory = $true)]
    [string]$BaseRef
)

$changedFiles = @(git diff --name-only "$BaseRef...HEAD" --)
if ($LASTEXITCODE -ne 0) {
    throw "Could not compare HEAD with $BaseRef"
}

$boundaries = [ordered]@{
    "Credentials and authentication" = '^(src-tauri/src/auth/|src-tauri/src/types\.rs$|src-tauri/src/commands/(account|oauth)\.rs$)'
    "Network requests and endpoints" = '^(src-tauri/src/api/|src-tauri/src/auth/token_refresh\.rs$|src-tauri/src/commands/usage\.rs$|src/.*(api|auth|update))'
    "Process execution" = '^(src-tauri/src/commands/(process|desktop_reopen)\.rs$|src-tauri/src/lib\.rs$|scripts/)'
    "Tauri permissions and updater" = '^(src-tauri/capabilities/|src-tauri/tauri\.conf\.json$|src/components/UpdateChecker\.tsx$)'
    "Dependencies and supply chain" = '^(package\.json$|pnpm-lock\.yaml$|src-tauri/Cargo\.(toml|lock)$|\.github/workflows/)'
    "Import, export, and local web access" = '^(src-tauri/src/(web/|commands/account\.rs$)|src/.*(import|export))'
}

$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add("## Security impact")
$lines.Add("")
$matched = $false

foreach ($boundary in $boundaries.GetEnumerator()) {
    $files = @($changedFiles | Where-Object { $_ -match $boundary.Value })
    if ($files.Count -eq 0) {
        continue
    }

    $matched = $true
    $lines.Add("### $($boundary.Key)")
    $lines.Add("")
    foreach ($file in $files) {
        $lines.Add("- ``$file``")
    }
    $lines.Add("")
}

if (-not $matched) {
    $lines.Add("No configured security-boundary files changed.")
    $lines.Add("")
}

$lines.Add("Changed files: $($changedFiles.Count). This report is a review aid, not an approval.")
$report = $lines -join [Environment]::NewLine

if ($env:GITHUB_STEP_SUMMARY) {
    Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value $report
} else {
    Write-Output $report
}
