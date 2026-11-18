#!/usr/bin/env bash
# shell-test.sh
# Demonstrates namespace-specific shell execution detection
# Verifies that identical actions generate CRITICAL in prod, WARNING in staging, and NOTICE in dev.

set -euo pipefail

echo "================================================================="
echo "  SCENARIO 1: Interactive Shell Execution Across Namespaces"
echo "================================================================="

# Discover pod names
PROD_POD=$(kubectl get pod -n prod -l app=nginx -o jsonpath='{.items[0].metadata.name}')
STAGING_POD=$(kubectl get pod -n staging -l app=nginx -o jsonpath='{.items[0].metadata.name}')
DEV_POD=$(kubectl get pod -n dev -l app=nginx -o jsonpath='{.items[0].metadata.name}')

echo "[*] Found Target Pods:"
echo "    - Prod:    $PROD_POD (namespace: prod)"
echo "    - Staging: $STAGING_POD (namespace: staging)"
echo "    - Dev:     $DEV_POD (namespace: dev)"
echo ""

echo "[1/3] Triggering Shell in Production container..."
echo "      Command: kubectl exec -n prod $PROD_POD -- /bin/sh -c 'echo shell_in_prod'"
kubectl exec -n prod "$PROD_POD" -- /bin/sh -c "echo 'prod shell execution'"
echo "      --> Expected Falco Priority: CRITICAL"
echo ""

echo "[2/3] Triggering Shell in Staging container..."
echo "      Command: kubectl exec -n staging $STAGING_POD -- /bin/sh -c 'echo shell_in_staging'"
kubectl exec -n staging "$STAGING_POD" -- /bin/sh -c "echo 'staging shell execution'"
echo "      --> Expected Falco Priority: WARNING"
echo ""

echo "[3/3] Triggering Shell in Development container..."
echo "      Command: kubectl exec -n dev $DEV_POD -- /bin/sh -c 'echo shell_in_dev'"
kubectl exec -n dev "$DEV_POD" -- /bin/sh -c "echo 'dev shell execution'"
echo "      --> Expected Falco Priority: NOTICE"
echo ""

echo "[*] Fetching recent Falco alerts:"
echo "-----------------------------------------------------------------"
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=10 | grep -E "Shell spawned" || true
echo "-----------------------------------------------------------------"
echo "[+] Shell execution test complete."
