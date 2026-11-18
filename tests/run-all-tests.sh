#!/usr/bin/env bash
# run-all-tests.sh
# Unified test runner for the Kubernetes Runtime Security Lab in bash / Linux / WSL

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

echo "Running Scenario 1: Shell execution..."
bash "$DIR/shell-test.sh"
echo ""

echo "Running Scenario 2: Sensitive file access..."
bash "$DIR/file-access-test.sh"
echo ""

echo "Running Scenario 3: Suspicious network activity..."
bash "$DIR/network-test.sh"
echo ""

echo "Running Scenario 4: Privilege escalation & credentials..."
bash "$DIR/privilege-test.sh"
echo ""

echo "[+] All runtime security scenario tests completed successfully!"
