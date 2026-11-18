#!/usr/bin/env bash
# network-test.sh
# Demonstrates suspicious network activity detection:
# - Reverse shell connection attempts to non-standard ports (4444)
# - Netcat socket creation / listening
# - Workload attempts to contact Kubernetes API directly

set -euo pipefail

echo "================================================================="
echo "  SCENARIO 3: Suspicious Network Activity Detection"
echo "================================================================="

PROD_POD=$(kubectl get pod -n prod -l app=nginx -o jsonpath='{.items[0].metadata.name}')
MON_POD=$(kubectl get pod -n monitoring -l app=sec-test-runner -o jsonpath='{.items[0].metadata.name}')

echo "[*] Target Pods: Prod: $PROD_POD | Monitoring: $MON_POD"
echo ""

echo "[1/3] Triggering Netcat socket listener in PRODUCTION container..."
echo "      Command: kubectl exec -n prod $PROD_POD -- nc -l -p 8080 -w 1"
kubectl exec -n prod "$PROD_POD" -- nc -l -p 8080 -w 1 2>&1 || true
echo "      --> Expected Falco Priority: ERROR (Netcat network activity)"
echo ""

echo "[2/3] Simulating outbound connection to typical reverse shell port 4444..."
echo "      Command: kubectl exec -n prod $PROD_POD -- nc -w 1 127.0.0.1 4444"
kubectl exec -n prod "$PROD_POD" -- nc -w 1 127.0.0.1 4444 2>&1 || true
echo "      --> Expected Falco Priority: CRITICAL / ERROR"
echo ""

echo "[3/3] Workload connecting directly to Kubernetes API Server..."
echo "      Command: kubectl exec -n prod $PROD_POD -- wget -T 1 --spider --no-check-certificate https://kubernetes.default.svc:443"
kubectl exec -n prod "$PROD_POD" -- wget -T 1 --spider --no-check-certificate https://kubernetes.default.svc:443 2>&1 || true
echo "      --> Expected Falco Priority: ERROR (Workload direct API connection)"
echo ""

echo "[*] Fetching recent Falco alerts:"
echo "-----------------------------------------------------------------"
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=15 | grep -E "Netcat|reverse shell|Kubernetes API" || true
echo "-----------------------------------------------------------------"
echo "[+] Network test complete."
