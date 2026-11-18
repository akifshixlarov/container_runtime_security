# run-all-tests.ps1
# Unified test runner for the Kubernetes Runtime Security Lab on Windows / PowerShell

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "      KUBERNETES RUNTIME SECURITY LAB - FULL TEST SUITE" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

$PROD_POD = kubectl get pod -n prod -l app=nginx -o jsonpath='{.items[0].metadata.name}'
$STAGING_POD = kubectl get pod -n staging -l app=nginx -o jsonpath='{.items[0].metadata.name}'
$DEV_POD = kubectl get pod -n dev -l app=nginx -o jsonpath='{.items[0].metadata.name}'

Write-Host "[+] Identified Target Pods:" -ForegroundColor Green
Write-Host "    - Production:  $PROD_POD"
Write-Host "    - Staging:     $STAGING_POD"
Write-Host "    - Development: $DEV_POD"
Write-Host ""

# TEST 1: Shell Execution
Write-Host "--- [TEST 1] NAMESPACE-SPECIFIC SHELL EXECUTION ---" -ForegroundColor Yellow
Write-Host "1.1 Executing shell in PROD..."
kubectl exec -n prod $PROD_POD -- /bin/sh -c "echo shell_prod_test"
Write-Host "1.2 Executing shell in STAGING..."
kubectl exec -n staging $STAGING_POD -- /bin/sh -c "echo shell_staging_test"
Write-Host "1.3 Executing shell in DEV..."
kubectl exec -n dev $DEV_POD -- /bin/sh -c "echo shell_dev_test"

# TEST 2: File Access
Write-Host ""
Write-Host "--- [TEST 2] SENSITIVE FILE ACCESS & USER ENUMERATION ---" -ForegroundColor Yellow
Write-Host "2.1 Reading /etc/shadow in PROD..."
kubectl exec -n prod $PROD_POD -- cat /etc/shadow 2>$null | Select-Object -First 3
Write-Host "2.2 Reading /etc/passwd in PROD..."
kubectl exec -n prod $PROD_POD -- cat /etc/passwd 2>$null | Select-Object -First 3
Write-Host "2.3 Reading /etc/passwd in DEV..."
kubectl exec -n dev $DEV_POD -- cat /etc/passwd 2>$null | Select-Object -First 3

# TEST 3: Network Activity
Write-Host ""
Write-Host "--- [TEST 3] SUSPICIOUS PROCESSES & NETWORK BEHAVIOR ---" -ForegroundColor Yellow
Write-Host "3.1 Netcat listener in PROD..."
kubectl exec -n prod $PROD_POD -- nc -l -p 8080 -w 1 2>&1 | Out-Null
Write-Host "3.2 Outbound connection to port 4444 in PROD..."
kubectl exec -n prod $PROD_POD -- nc -w 1 127.0.0.1 4444 2>&1 | Out-Null
Write-Host "3.3 Direct connection to Kubernetes API Server..."
kubectl exec -n prod $PROD_POD -- wget -T 1 --spider --no-check-certificate https://kubernetes.default.svc:443 2>&1 | Out-Null

# TEST 4: Privilege Escalation & Service Account Token
Write-Host ""
Write-Host "--- [TEST 4] PRIVILEGE ESCALATION & KUBERNETES TOKEN ACCESS ---" -ForegroundColor Yellow
Write-Host "4.1 Invoking 'su' binary in PROD..."
kubectl exec -n prod $PROD_POD -- su -c "id"
Write-Host "4.2 Reading mounted Service Account token in PROD..."
kubectl exec -n prod $PROD_POD -- cat /var/run/secrets/kubernetes.io/serviceaccount/token | Select-Object -First 1 | ForEach-Object { $_.Substring(0, 30) + "..." }

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "                 FALCO RUNTIME ALERTS SUMMARY                    " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Start-Sleep -Seconds 2
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=25
