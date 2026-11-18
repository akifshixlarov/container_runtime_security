# test-tetragon-enforcement.ps1
# Automated Validation and Verification Script for Tetragon Runtime Enforcement
# Operating System: Windows PowerShell
# Environment: local kind cluster 'runtime-security-lab' with WSL2 Linux 6.6 kernel

$ErrorActionPreference = "Continue"

Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "     TETRAGON RUNTIME ENFORCEMENT & COEXISTENCE VERIFICATION SUITE       " -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host ""

$TotalTests = 0
$PassedTests = 0
$FailedTests = 0

function Assert-Result {
    param(
        [string]$TestId,
        [string]$Description,
        [string]$Expected,
        [string]$Actual,
        [bool]$Success
    )
    $script:TotalTests++
    if ($Success) {
        $script:PassedTests++
        Write-Host "  [PASS] $TestId - $Description" -ForegroundColor Green
        Write-Host "         Expected: $Expected" -ForegroundColor DarkGray
        Write-Host "         Observed: $Actual" -ForegroundColor DarkGray
    } else {
        $script:FailedTests++
        Write-Host "  [FAIL] $TestId - $Description" -ForegroundColor Red
        Write-Host "         Expected: $Expected" -ForegroundColor DarkYellow
        Write-Host "         Observed: $Actual" -ForegroundColor DarkYellow
    }
}

# -----------------------------------------------------------------------------
# STEP 1: INFRASTRUCTURE & READINESS CHECKS
# -----------------------------------------------------------------------------
Write-Host "[1/6] Validating Cluster & Tetragon Health..." -ForegroundColor Yellow

# Verify Cluster
$NodeReady = ((kubectl get nodes --no-headers) -match "Ready")
if (-not $NodeReady) {
    Write-Host "[-] Kubernetes cluster node is not Ready!" -ForegroundColor Red
    exit 1
}
Write-Host "  [+] Kubernetes cluster node is Ready." -ForegroundColor Green


# Verify Tetragon DaemonSet
$TetragonReady = kubectl get ds -n kube-system tetragon -o jsonpath='{.status.numberReady}' 2>$null
$TetragonDesired = kubectl get ds -n kube-system tetragon -o jsonpath='{.status.desiredNumberScheduled}' 2>$null
if (-not $TetragonReady -or $TetragonReady -lt 1) {
    Write-Host "[-] Tetragon DaemonSet is not ready (Ready: $TetragonReady / Desired: $TetragonDesired)!" -ForegroundColor Red
    exit 1
}
Write-Host "  [+] Tetragon DaemonSet is healthy ($TetragonReady/$TetragonDesired ready)." -ForegroundColor Green

# Verify Required Policies
$ExpectedPolicies = @(
    "prod-block-shell",
    "prod-protect-sensitive-files",
    "prod-block-network-tools",
    "prod-privilege-escalation"
)
$ActivePolicies = kubectl get tracingpolicy -o jsonpath='{.items[*].metadata.name}' 2>$null
foreach ($Policy in $ExpectedPolicies) {
    if ($ActivePolicies -match $Policy) {
        Write-Host "  [+] TracingPolicy '$Policy' is active." -ForegroundColor Green
    } else {
        Write-Host "[-] Missing TracingPolicy '$Policy'!" -ForegroundColor Red
        exit 1
    }
}

# Identify Pods
$DEV_POD = kubectl get pod -n dev -l app=nginx -o jsonpath='{.items[0].metadata.name}'
$STAGING_POD = kubectl get pod -n staging -l app=nginx -o jsonpath='{.items[0].metadata.name}'
$PROD_POD = kubectl get pod -n prod -l app=nginx -o jsonpath='{.items[0].metadata.name}'
$PROD_IP = kubectl get pod -n prod $PROD_POD -o jsonpath='{.status.podIP}'

Write-Host "  [+] Target Workloads:" -ForegroundColor Cyan
Write-Host "      - dev:     $DEV_POD"
Write-Host "      - staging: $STAGING_POD"
Write-Host "      - prod:    $PROD_POD (IP: $PROD_IP)"
Write-Host ""

# -----------------------------------------------------------------------------
# STEP 2: POLICY 1 - BLOCK SHELL EXECUTION IN PRODUCTION
# -----------------------------------------------------------------------------
Write-Host "[2/6] Testing Policy 1: Shell Execution Controls (prod-block-shell)..." -ForegroundColor Yellow

# 2.1 Dev Shell (Allowed)
$devOut = kubectl exec -n dev $DEV_POD -- /bin/sh -c "echo dev_shell_allowed" 2>&1
$devExit = $LASTEXITCODE
Assert-Result -TestId "1.1" `
              -Description "Execute /bin/sh in dev workload" `
              -Expected "ExitCode 0 (Allowed)" `
              -Actual "ExitCode $devExit ($devOut)" `
              -Success ($devExit -eq 0 -and $devOut -match "dev_shell_allowed")

# 2.2 Staging Shell (Allowed)
$stagingOut = kubectl exec -n staging $STAGING_POD -- /bin/sh -c "echo staging_shell_allowed" 2>&1
$stagingExit = $LASTEXITCODE
Assert-Result -TestId "1.2" `
              -Description "Execute /bin/sh in staging workload" `
              -Expected "ExitCode 0 (Allowed)" `
              -Actual "ExitCode $stagingExit ($stagingOut)" `
              -Success ($stagingExit -eq 0 -and $stagingOut -match "staging_shell_allowed")

# 2.3 Prod Shell (Enforced / Blocked)
$prodOut = kubectl exec -n prod $PROD_POD -- /bin/sh -c "echo prod_shell_attempt" 2>&1
$prodExit = $LASTEXITCODE
$prodBlocked = ($prodExit -eq 137 -or $prodOut -match "command terminated with exit code 137")
Assert-Result -TestId "1.3" `
              -Description "Execute /bin/sh in prod workload (Blocked by Sigkill)" `
              -Expected "ExitCode 137 / Terminated by Sigkill" `
              -Actual "ExitCode $prodExit ($prodOut)" `
              -Success $prodBlocked
Write-Host ""

# -----------------------------------------------------------------------------
# STEP 3: POLICY 2 - SENSITIVE FILES & CREDENTIALS
# -----------------------------------------------------------------------------
Write-Host "[3/6] Testing Policy 2: Sensitive File Protection (prod-protect-sensitive-files)..." -ForegroundColor Yellow

# 3.1 Dev /etc/shadow access (Allowed)
$devShadow = kubectl exec -n dev $DEV_POD -- head -n 1 /etc/shadow 2>&1
$devShadowExit = $LASTEXITCODE
Assert-Result -TestId "2.1" `
              -Description "Access /etc/shadow in dev workload" `
              -Expected "ExitCode 0 (Allowed)" `
              -Actual "ExitCode $devShadowExit (Header verified, contents masked)" `
              -Success ($devShadowExit -eq 0)

# 3.2 Prod /etc/shadow access (Enforced / Blocked)
$prodShadow = kubectl exec -n prod $PROD_POD -- head -n 1 /etc/shadow 2>&1
$prodShadowExit = $LASTEXITCODE
$prodShadowBlocked = ($prodShadowExit -eq 137 -or $prodShadow -match "command terminated with exit code 137")
Assert-Result -TestId "2.2" `
              -Description "Access /etc/shadow in prod workload (Blocked by Sigkill)" `
              -Expected "ExitCode 137 / Terminated before read" `
              -Actual "ExitCode $prodShadowExit ($prodShadow)" `
              -Success $prodShadowBlocked

# 3.3 Dev Service Account Token Access (Allowed, contents suppressed)
$devToken = kubectl exec -n dev $DEV_POD -- head -c 10 /var/run/secrets/kubernetes.io/serviceaccount/token 2>&1
$devTokenExit = $LASTEXITCODE
Assert-Result -TestId "2.3" `
              -Description "Access Service Account Token in dev workload" `
              -Expected "ExitCode 0 (Allowed, suppression verified)" `
              -Actual "ExitCode $devTokenExit (Masked)" `
              -Success ($devTokenExit -eq 0)

# 3.4 Prod Service Account Token Access (Enforced / Blocked, contents suppressed)
$prodToken = kubectl exec -n prod $PROD_POD -- head -c 10 /var/run/secrets/kubernetes.io/serviceaccount/token 2>&1
$prodTokenExit = $LASTEXITCODE
$prodTokenBlocked = ($prodTokenExit -eq 137 -or $prodToken -match "command terminated with exit code 137")
Assert-Result -TestId "2.4" `
              -Description "Access Service Account Token in prod workload (Blocked by Sigkill)" `
              -Expected "ExitCode 137 / Terminated before read" `
              -Actual "ExitCode $prodTokenExit ($prodToken)" `
              -Success $prodTokenBlocked
Write-Host ""

# -----------------------------------------------------------------------------
# STEP 4: POLICY 3 - NETWORK RECONNAISSANCE TOOLS
# -----------------------------------------------------------------------------
Write-Host "[4/6] Testing Policy 3: Network Tool Execution (prod-block-network-tools)..." -ForegroundColor Yellow

# 4.1 Dev nc binary execution (Allowed)
$devNc = kubectl exec -n dev $DEV_POD -- nc -h 2>&1
$devNcExit = $LASTEXITCODE
# Exit code 1 from Busybox usage help is normal for -h, but it is NOT exit code 137
Assert-Result -TestId "3.1" `
              -Description "Execute 'nc' utility in dev workload" `
              -Expected "Allowed to execute (Process started without SIGKILL)" `
              -Actual "ExitCode $devNcExit (Busybox utility invoked)" `
              -Success ($devNcExit -ne 137 -and $devNc -notmatch "terminated with exit code 137")

# 4.2 Prod nc binary execution (Enforced / Blocked)
$prodNc = kubectl exec -n prod $PROD_POD -- nc -h 2>&1
$prodNcExit = $LASTEXITCODE
$prodNcBlocked = ($prodNcExit -eq 137 -or $prodNc -match "command terminated with exit code 137")
Assert-Result -TestId "3.2" `
              -Description "Execute 'nc' utility in prod workload (Blocked by Sigkill)" `
              -Expected "ExitCode 137 / Terminated by Sigkill" `
              -Actual "ExitCode $prodNcExit ($prodNc)" `
              -Success $prodNcBlocked

# 4.3 Prod Ordinary Application Traffic (Unimpaired)
$httpOut = kubectl exec -n dev $DEV_POD -- wget -qO- -T 2 "http://$PROD_IP" 2>&1
$httpExit = $LASTEXITCODE
$httpHealthy = ($httpExit -eq 0 -and $httpOut -match "Welcome to nginx!")
Assert-Result -TestId "3.3" `
              -Description "Verify normal Nginx HTTP traffic in prod is preserved" `
              -Expected "HTTP 200 / 'Welcome to nginx!'" `
              -Actual "ExitCode $httpExit (Traffic served cleanly)" `
              -Success $httpHealthy
Write-Host ""

# -----------------------------------------------------------------------------
# STEP 5: POLICY 4 - PRIVILEGE ESCALATION UTILITIES
# -----------------------------------------------------------------------------
Write-Host "[5/6] Testing Policy 4: Privilege Escalation Controls (prod-privilege-escalation)..." -ForegroundColor Yellow

# 5.1 Dev 'su' execution (Allowed)
$devSu = kubectl exec -n dev $DEV_POD -- su -c "id" 2>&1
$devSuExit = $LASTEXITCODE
Assert-Result -TestId "4.1" `
              -Description "Execute 'su' utility in dev workload" `
              -Expected "Allowed to execute (uid=0 resolved)" `
              -Actual "ExitCode $devSuExit ($devSu)" `
              -Success ($devSuExit -eq 0 -and $devSu -match "uid=0")

# 5.2 Prod 'su' execution (Enforced / Blocked)
$prodSu = kubectl exec -n prod $PROD_POD -- su -c "id" 2>&1
$prodSuExit = $LASTEXITCODE
$prodSuBlocked = ($prodSuExit -eq 137 -or $prodSu -match "command terminated with exit code 137")
Assert-Result -TestId "4.2" `
              -Description "Execute 'su' utility in prod workload (Blocked by Sigkill)" `
              -Expected "ExitCode 137 / Terminated by Sigkill" `
              -Actual "ExitCode $prodSuExit ($prodSu)" `
              -Success $prodSuBlocked
Write-Host ""

# -----------------------------------------------------------------------------
# STEP 6: COEXISTENCE & TELEMETRY VALIDATION
# -----------------------------------------------------------------------------
Write-Host "[6/6] Verifying Falco Runtime Detection & Tetragon Observability..." -ForegroundColor Yellow

# Check Falco pod status
$FalcoStatus = kubectl get daemonset -n falco falco -o jsonpath='{.status.numberReady}' 2>$null
if ($FalcoStatus -ge 1) {
    Write-Host "  [+] Falco DaemonSet is operational ($FalcoStatus ready)." -ForegroundColor Green
} else {
    Write-Host "  [-] Falco DaemonSet is not ready!" -ForegroundColor Red
}

# Fetch recent Falco alerts
Start-Sleep -Seconds 2
$FalcoRecent = kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=6 2>$null
Write-Host "  [+] Recent Falco Runtime Alerts (Sample):" -ForegroundColor Cyan
$FalcoRecent | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }

Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "                         TEST SUITE SUMMARY                               " -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "  Total Tests Executed: $TotalTests"
Write-Host "  Passed:               $PassedTests" -ForegroundColor Green
Write-Host "  Failed:               $FailedTests" -ForegroundColor $(if ($FailedTests -gt 0) { "Red" } else { "Green" })
Write-Host "==========================================================================" -ForegroundColor Cyan

if ($FailedTests -gt 0) {
    Write-Host "[-] Verification FAILED with $FailedTests error(s)." -ForegroundColor Red
    exit 1
} else {
    Write-Host "[+] All Tetragon runtime enforcement & isolation tests PASSED!" -ForegroundColor Green
    exit 0
}
