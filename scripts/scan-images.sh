#!/usr/bin/env bash
# scan-images.sh - Automated Trivy Image Vulnerability Scanner
# Targets: nginx:alpine (default) and alpine:latest

set -eo pipefail

IMAGE_NAME="${1:-nginx:alpine}"
OUTPUT_PATH="${2:-reports/trivy-nginx-report.json}"
SCANNERS="${3:-vuln,secret}"

mkdir -p "$(dirname "$OUTPUT_PATH")"

echo "=========================================================================="
echo "         KUBERNETES RUNTIME SECURITY LAB - TRIVY SCANNER                  "
echo "=========================================================================="
echo "[+] Target Image:      $IMAGE_NAME"
echo "[+] Destination File:  $OUTPUT_PATH"
echo "[+] Enabled Scanners:  $SCANNERS"

if command -v trivy &>/dev/null; then
    echo "[+] Using locally installed Trivy binary."
    trivy image --format json --scanners "$SCANNERS" --output "$OUTPUT_PATH" "$IMAGE_NAME"
elif command -v docker &>/dev/null; then
    echo "[+] Trivy binary not found. Falling back to containerized Trivy via Docker."
    ABS_OUT_DIR="$(cd "$(dirname "$OUTPUT_PATH")" && pwd)"
    OUT_FILE="$(basename "$OUTPUT_PATH")"
    docker run --rm \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v "$ABS_OUT_DIR":/reports \
        aquasec/trivy:latest image \
        --format json \
        --scanners "$SCANNERS" \
        --output "/reports/$OUT_FILE" \
        "$IMAGE_NAME"
else
    echo "[-] Error: Neither 'trivy' nor 'docker' is available in the current PATH." >&2
    exit 1
fi

if [[ -s "$OUTPUT_PATH" ]]; then
    echo "[+] Scan completed successfully. Report written to: $OUTPUT_PATH"
else
    echo "[-] Scan failed or produced an empty report." >&2
    exit 1
fi
