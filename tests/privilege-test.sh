#!/usr/bin/env bash
# privilege-test.sh
# Demonstrates suspicious privilege escalation & Kubernetes credential theft detection:
# - Invoking su / sudo binaries inside containers
# - Workload reading mounted Service Account token credentials (/var/run/secrets/...)

set -euo pipefail

echo "================================================================="
echo "  SCENARIO 4: Privilege Escalation & Credential Access"
echo "================================================================="

PROD_POD=$(kubectl get pod -n prod -l app=nginx -o jsonpath='{.items[0].metadata.name}')
STAGING_POD=$(kubectl get pod -n staging -l app=nginx -o jsonpath='{.items[0].metadata.name}')

echo "[*] Target Pods: Prod: $PROD_POD | Staging: $STAGING_POD"
echo ""

echo "[1/3] Triggering privilege escalation utility (su) in PRODUCTION container..."
echo "      Command: kubectl exec -n prod $PROD_POD -- su -c 'id'"
kubectl exec -n prod "$PROD_POD" -- su -c "id" || true
echo "      --> Expected Falco Priority: ERROR (Privilege escalation binary invoked)"
echo ""

echo "[2/3] Accessing Kubernetes Service Account token in PRODUCTION container..."
echo "      Command: kubectl exec -n prod $PROD_POD -- cat /var/run/secrets/kubernetes.io/serviceaccount/token"
kubectl exec -n prod "$PROD_POD" -- head -c 30 /var/run/secrets/kubernetes.io/serviceaccount/token || true
echo ""
echo "      --> Expected Falco Priority: CRITICAL (Workload accessed Service Account token in prod)"
echo ""

echo "[3/3] Accessing Kubernetes Service Account token in STAGING container..."
echo "      Command: kubectl exec -n staging $STAGING_POD -- cat /var/run/secrets/kubernetes.io/serviceaccount/token"
kubectl exec -n staging "$STAGING_POD" -- head -c 30 /var/run/secrets/kubernetes.io/serviceaccount/token || true
echo ""
echo "      --> Expected Falco Priority: WARNING (Workload accessed token in non-prod)"
echo ""

echo "[*] Fetching recent Falco alerts:"
echo "-----------------------------------------------------------------"
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=15 | grep -E "Privilege|Service Account" || true
echo "-----------------------------------------------------------------"
echo "[+] Privilege and credential access test complete."
