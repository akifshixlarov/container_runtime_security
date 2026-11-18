<#
.SYNOPSIS
    Imports or re-imports Trivy vulnerability scan reports into DefectDojo via the official REST API v2.

.DESCRIPTION
    Automates DefectDojo Product, Engagement, and Test management for the Kubernetes Runtime Security Lab.
    Uses environment variables or a local .env file for authentication (no hardcoded credentials).
    Supports initial import (/api/v2/import-scan/) and deduplicating re-import (/api/v2/reimport-scan/).

.PARAMETER ReportPath
    Path to the Trivy JSON report (defaults to "reports/trivy-nginx-report.json").

.PARAMETER ProductName
    Target DefectDojo Product name (defaults to "Kubernetes Runtime Security Lab").

.PARAMETER EngagementName
    Target DefectDojo Engagement name (defaults to "Container Image Vulnerability Scans").

.PARAMETER Reimport
    If specified, performs a re-import scan on the existing test, updating findings and testing deduplication.

.PARAMETER DefectDojoUrl
    Base URL of DefectDojo instance (defaults to value from .env or http://localhost:8080).

.PARAMETER ApiToken
    DefectDojo DRF API v2 Token (defaults to value from .env or DEFECTDOJO_API_TOKEN environment variable).

.EXAMPLE
    .\scripts\import-trivy-findings.ps1

.EXAMPLE
    .\scripts\import-trivy-findings.ps1 -Reimport
#>

[CmdletBinding()]
param (
    [string]$ReportPath = "reports/trivy-nginx-report.json",
    [string]$ProductName = "Kubernetes Runtime Security Lab",
    [string]$EngagementName = "Container Image Vulnerability Scans",
    [switch]$Reimport,
    [string]$DefectDojoUrl,
    [string]$ApiToken,
    [string]$EnvFile = ".env"
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "      KUBERNETES RUNTIME SECURITY LAB - DEFECTDOJO SCAN IMPORTER          " -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan

# 1. Load credentials from .env file if available
if (Test-Path $EnvFile) {
    Write-Host "[+] Reading configuration from $EnvFile..." -ForegroundColor Gray
    Get-Content $EnvFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#") -and $line.Contains("=")) {
            $parts = $line.Split("=", 2)
            $k = $parts[0].Trim()
            $v = $parts[1].Trim().Trim('"').Trim("'")
            if (-not [string]::IsNullOrEmpty($k) -and [string]::IsNullOrEmpty([System.Environment]::GetEnvironmentVariable($k))) {
                [System.Environment]::SetEnvironmentVariable($k, $v)
            }
        }
    }
}

# Resolve parameters with fallback to environment variables
if ([string]::IsNullOrEmpty($DefectDojoUrl)) {
    $DefectDojoUrl = [System.Environment]::GetEnvironmentVariable("DEFECTDOJO_URL")
    if ([string]::IsNullOrEmpty($DefectDojoUrl)) { $DefectDojoUrl = "http://localhost:8080" }
}
$DefectDojoUrl = $DefectDojoUrl.TrimEnd('/')

if ([string]::IsNullOrEmpty($ApiToken)) {
    $ApiToken = [System.Environment]::GetEnvironmentVariable("DEFECTDOJO_API_TOKEN")
}

if ([string]::IsNullOrEmpty($ApiToken)) {
    Write-Error @"
DefectDojo API Token not configured!
Please provide an API token using one of the following methods:
  1. Add DEFECTDOJO_API_TOKEN=your_token to your local .env file
  2. Set `$env:DEFECTDOJO_API_TOKEN = 'your_token'
  3. Pass -ApiToken 'your_token' parameter

To generate an API token for user 'admin':
  docker exec django-defectdojo-uwsgi-1 python manage.py drf_create_token admin
"@
    exit 1
}

# Validate report file
$resolvedReport = [System.IO.Path]::GetFullPath($ReportPath)
if (-not (Test-Path $resolvedReport)) {
    Write-Error "Scan report file not found at: $resolvedReport. Please run .\scripts\scan-images.ps1 first."
    exit 1
}

# 2. Check DefectDojo Connectivity
Write-Host "[*] Connecting to DefectDojo at $DefectDojoUrl..." -ForegroundColor Cyan
$headers = @{
    "Authorization" = "Token $ApiToken"
    "Accept"        = "application/json"
}

try {
    $profile = Invoke-RestMethod -Uri "$DefectDojoUrl/api/v2/user_profile/" -Headers $headers -Method Get -TimeoutSec 10
    Write-Host "[+] Authenticated as user: '$($profile.user.username)' ($($profile.user.email))" -ForegroundColor Green
} catch {
    Write-Error "Failed to authenticate with DefectDojo: $_. Ensure DefectDojo is running and the API token is valid."
    exit 1
}

# 3. Ensure Product exists
Write-Host "[*] Checking for Product: '$ProductName'..." -ForegroundColor Cyan
$encodedProdName = [System.Uri]::EscapeDataString($ProductName)
$prodRes = Invoke-RestMethod -Uri "$DefectDojoUrl/api/v2/products/?name=$encodedProdName" -Headers $headers -Method Get

$productId = $null
if ($prodRes.count -gt 0) {
    $productId = $prodRes.results[0].id
    Write-Host "[+] Found existing Product (ID: $productId)" -ForegroundColor Green
} else {
    Write-Host "[*] Product not found. Creating Product '$ProductName'..." -ForegroundColor Yellow
    $createProdBody = @{
        name                          = $ProductName
        description                   = "DefectDojo Vulnerability Management for Kubernetes Runtime Security Lab Workloads"
        prod_type                     = 1
        enable_simple_risk_acceptance = $true
    } | ConvertTo-Json
    
    $headersJson = $headers.Clone()
    $headersJson["Content-Type"] = "application/json"
    $newProd = Invoke-RestMethod -Uri "$DefectDojoUrl/api/v2/products/" -Headers $headersJson -Method Post -Body $createProdBody
    $productId = $newProd.id
    Write-Host "[+] Created Product (ID: $productId)" -ForegroundColor Green
}

# 4. Ensure Engagement exists
Write-Host "[*] Checking for Engagement: '$EngagementName'..." -ForegroundColor Cyan
$encodedEngName = [System.Uri]::EscapeDataString($EngagementName)
$engRes = Invoke-RestMethod -Uri "$DefectDojoUrl/api/v2/engagements/?product=$productId&name=$encodedEngName" -Headers $headers -Method Get

$engagementId = $null
if ($engRes.count -gt 0) {
    $engagementId = $engRes.results[0].id
    Write-Host "[+] Found existing Engagement (ID: $engagementId)" -ForegroundColor Green
} else {
    Write-Host "[*] Engagement not found. Creating Engagement '$EngagementName'..." -ForegroundColor Yellow
    $createEngBody = @{
        name            = $EngagementName
        product         = $productId
        target_start    = (Get-Date).ToString("yyyy-MM-dd")
        target_end      = (Get-Date).AddMonths(1).ToString("yyyy-MM-dd")
        status          = "In Progress"
        engagement_type = "Interactive"
    } | ConvertTo-Json
    
    $headersJson = $headers.Clone()
    $headersJson["Content-Type"] = "application/json"
    $newEng = Invoke-RestMethod -Uri "$DefectDojoUrl/api/v2/engagements/" -Headers $headersJson -Method Post -Body $createEngBody
    $engagementId = $newEng.id
    Write-Host "[+] Created Engagement (ID: $engagementId)" -ForegroundColor Green
}

# 5. Check for Existing Test (for Reimport option)
$testRes = Invoke-RestMethod -Uri "$DefectDojoUrl/api/v2/tests/?engagement=$engagementId" -Headers $headers -Method Get
$existingTest = $null
if ($testRes.count -gt 0) {
    $existingTest = $testRes.results | Where-Object { $_.test_type_name -eq "Trivy Scan" } | Select-Object -First 1
}

$isReimport = $Reimport.IsPresent -and ($null -ne $existingTest)
$testId = $null

if ($isReimport) {
    $testId = $existingTest.id
    Write-Host "==========================================================================" -ForegroundColor Magenta
    Write-Host "[*] Performing RE-IMPORT onto existing Test ID: $testId..." -ForegroundColor Magenta
    Write-Host "==========================================================================" -ForegroundColor Magenta
    
    # Use curl.exe for reliable multipart file upload
    $uploadResult = & curl.exe -s -X POST "$DefectDojoUrl/api/v2/reimport-scan/" `
        -H "Authorization: Token $ApiToken" `
        -F "scan_type=Trivy Scan" `
        -F "test=$testId" `
        -F "file=@$resolvedReport" `
        -F "active=true" `
        -F "verified=true" `
        -F "close_old_findings=true"
    
    try {
        $importJson = $uploadResult | ConvertFrom-Json
        Write-Host "[+] Re-import succeeded! Scan updated." -ForegroundColor Green
        if ($importJson.statistics -and $importJson.statistics.delta) {
            $delta = $importJson.statistics.delta
            Write-Host "  Deduplication & Delta Statistics:" -ForegroundColor Cyan
            Write-Host "    - Created:    $($delta.created.total.total)"
            Write-Host "    - Closed:     $($delta.closed.total.total)"
            Write-Host "    - Untouched:  $($delta.untouched.total.total)"
            Write-Host "    - Reactivated:$($delta.reactivated.total.total)"
        }
    } catch {
        Write-Warning "Could not parse re-import JSON response: $uploadResult"
    }
} else {
    Write-Host "==========================================================================" -ForegroundColor Green
    Write-Host "[*] Performing INITIAL IMPORT into Engagement ID: $engagementId..." -ForegroundColor Green
    Write-Host "==========================================================================" -ForegroundColor Green
    
    $uploadResult = & curl.exe -s -X POST "$DefectDojoUrl/api/v2/import-scan/" `
        -H "Authorization: Token $ApiToken" `
        -F "scan_type=Trivy Scan" `
        -F "engagement=$engagementId" `
        -F "file=@$resolvedReport" `
        -F "active=true" `
        -F "verified=true" `
        -F "close_old_findings=false"
    
    try {
        $importJson = $uploadResult | ConvertFrom-Json
        $testId = $importJson.test_id
        if (-not $testId) { $testId = $importJson.test }
        Write-Host "[+] Scan successfully imported into Test ID: $testId" -ForegroundColor Green
    } catch {
        Write-Error "Import failed: $uploadResult"
        exit 1
    }
}

# 6. Retrieve & Display Findings
Write-Host "`n[*] Fetching current findings for Test ID: $testId..." -ForegroundColor Cyan
$findingsRes = Invoke-RestMethod -Uri "$DefectDojoUrl/api/v2/findings/?test=$testId" -Headers $headers -Method Get

Write-Host "==========================================================================" -ForegroundColor Green
Write-Host "               DEFECTDOJO FINDINGS INVENTORY (TEST #$testId)              " -ForegroundColor Green
Write-Host "==========================================================================" -ForegroundColor Green
Write-Host "  Product:    $ProductName (ID: $productId)"
Write-Host "  Engagement: $EngagementName (ID: $engagementId)"
Write-Host "  Total Ingested Findings: $($findingsRes.count)"

$displayFindings = @()
foreach ($f in $findingsRes.results) {
    $cve = ""
    if ($f.vulnerability_ids -and $f.vulnerability_ids.Count -gt 0) {
        $cve = ($f.vulnerability_ids | ForEach-Object { $_.vulnerability_id }) -join ", "
    }
    $displayFindings += [PSCustomObject]@{
        ID           = $f.id
        Severity     = $f.severity
        CVE          = $cve
        Title        = $f.title
        Active       = $f.active
        Verified     = $f.verified
        RiskAccepted = $f.risk_accepted
    }
}

if ($displayFindings.Count -gt 0) {
    $displayFindings | Format-Table -AutoSize | Out-String | Write-Host
} else {
    Write-Host "  No findings recorded."
}

Write-Host "[+] Integration verification complete. View findings at: $DefectDojoUrl/test/$testId" -ForegroundColor Green
exit 0
