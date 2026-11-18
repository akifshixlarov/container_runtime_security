#!/usr/bin/env bash
# file-access-test.sh
# Demonstrates runtime detection of sensitive file and directory access
# Tests /etc/shadow, /etc/passwd, and sensitive directories across namespaces.

set -euo pipefail

echo "================================================================="
echo "  SCENARIO 2: Sensitive File & Directory Monitoring"
echo "================================================================="

PROD_POD=$(kubectl get pod -n prod -l app=nginx -o jsonpath='{.items[0].metadata.name}')
STAGING_POD=$(kubectl get pod -n staging -l app=nginx -o jsonpath='{.items[0].metadata.name}')
DEV_POD=$(kubectl get pod -n dev -l app=nginx -o jsonpath='{.items[0].metadata.name}')

echo "[*] Target Pods: Prod: $PROD_POD | Staging: $STAGING_POD | Dev: $DEV_POD"
echo ""

echo "[1/4] Attempting to read /etc/shadow in PRODUCTION container..."
echo "      Command: kubectl exec -n prod $PROD_POD -- cat /etc/shadow"
kubectl exec -n prod "$PROD_POD" -- head -n 3 /etc/shadow || true
echo "      --> Expected Falco Priority: CRITICAL / Warning"
echo ""

echo "[2/4] Attempting to read /etc/shadow in STAGING container..."
echo "      Command: kubectl exec -n staging $STAGING_POD -- cat /etc/shadow"
kubectl exec -n staging "$STAGING_POD" -- head -n 3 /etc/shadow || true
echo "      --> Expected Falco Priority: WARNING"
echo ""

echo "[3/4] Enumerating /etc/passwd in PRODUCTION container..."
echo "      Command: kubectl exec -n prod $PROD_POD -- cat /etc/passwd"
kubectl exec -n prod "$PROD_POD" -- head -n 3 /etc/passwd || true
echo "      --> Expected Falco Priority: ERROR (High severity user enumeration)"
echo ""

echo "[4/4] Enumerating /etc/passwd in DEVELOPMENT container..."
echo "      Command: kubectl exec -n dev $DEV_POD -- cat /etc/passwd"
kubectl exec -n dev "$DEV_POD" -- head -n 3 /etc/passwd || true
echo "      --> Expected Falco Priority: NOTICE (Informational in dev)"
echo ""

echo "[*] Fetching recent Falco alerts:"
echo "-----------------------------------------------------------------"
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=15 | grep -E "Sensitive|passwd|shadow" || true
echo "-----------------------------------------------------------------"
echo "[+] File access test complete."
