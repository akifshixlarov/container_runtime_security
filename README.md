# Kubernetes Container Runtime Security Lab: Falco Detection, Tetragon Enforcement & DefectDojo Vulnerability Management

[![Runtime Security CI](https://github.com/akifshixlarov/container_runtime_security/actions/workflows/ci.yml/badge.svg)](https://github.com/akifshixlarov/container_runtime_security/actions)
![Kubernetes](https://img.shields.io/badge/Kubernetes-v1.31.2-blue?logo=kubernetes)
![eBPF](https://img.shields.io/badge/Driver-eBPF-orange)
![Tetragon](https://img.shields.io/badge/Enforcement-Cilium_Tetragon-green)
![Falco](https://img.shields.io/badge/Detection-Falco-007acc)
![DefectDojo](https://img.shields.io/badge/Governance-OWASP_DefectDojo-red)
![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)

A reproducible, hands-on laboratory demonstrating defense-in-depth container security on Linux, macOS, and Windows (Docker Desktop / WSL2):
- **Falco**: Real-time behavioral detection and namespace-aware security alerting via modern eBPF.
- **Cilium Tetragon**: In-kernel preventive enforcement and synchronous process termination (`SIGKILL`, exit code 137) via eBPF kprobes and VFS hooks.
- **DefectDojo & Trivy**: Automated vulnerability management, container image CVE scanning, deduplication, and risk acceptance tracking.

---

## 1. Preventive Controls vs. Vulnerability Management vs. Runtime Security vs. Runtime Enforcement

Security across the container lifecycle operates across four complementary, non-overlapping layers:

| Dimension | Vulnerability Management (Trivy + DefectDojo) | Preventive / Admission Controls | Runtime Detection (Falco) | Runtime Enforcement (Tetragon) |
| :--- | :--- | :--- | :--- | :--- |
| **Primary Mechanism** | Automated image CVE scanning & centralized vulnerability governance | Policy enforcement at deployment / admission time | Continuous monitoring of Linux kernel system calls | Synchronous eBPF kernel tracing and process interception |
| **Examples** | **Trivy** (JSON scan) + **DefectDojo** (v2 REST API, deduplication) | RBAC, NetworkPolicy, Pod Security Admission (PSA), `securityContext` | **Falco** (modern eBPF probe, custom rules) | **Cilium Tetragon** (kprobes, tracepoints, TracingPolicies) |
| **Action Taken** | Tracks CVEs, records risk acceptance, manages remediation SLAs | Rejects non-compliant pods or blocks unauthorized traffic | Emits structured security alerts to stdout / SIEM | Synchronously terminates processes with `SIGKILL` (`exit code 137`) |
| **Lifecycle Phase** | Build, CI/CD, pre-deployment & continuous audit | Deployment / admission gatekeeping | Real-time observation during runtime execution | Real-time mitigation at the syscall / VFS boundary |
| **Limitation** | Cannot detect zero-days, memory corruption, or behavioral drift | Cannot inspect behavior within permitted binaries | Passive alerting; cannot block actions on its own | Restricted by kernel capabilities; does not patch image CVEs |
| **Role in this Lab** | Ingests, tracks, and manages container image vulnerabilities | Cluster infrastructure baseline | Visibility & audit trail across all namespaces (`dev`, `staging`, `prod`) | Active prevention of unauthorized actions in `prod` |

> **Defense-in-Depth Principle**: **Trivy & DefectDojo** ensure container base images are vetted and unpatched CVEs are tracked; **Falco** alerts on unexpected behaviors; and **Tetragon** guarantees that unauthorized actions (such as interactive shells or sensitive credential access) are terminated in-kernel before damage can occur.

---

## 2. System Architecture

```text
  ┌────────────────────────────────────────────────────────────────────────────────────────┐
  │                           HOST ENVIRONMENT (Windows / WSL2 / Docker)                   │
  └────────────────────────────────────────────────────────────────────────────────────────┘
                                    │                                  │
          ┌─────────────────────────┴───────────────┐                  │
          ▼                                         ▼                  ▼
┌──────────────────────────────────────┐  ┌────────────────────────────────────────────────┐
│   VULNERABILITY MANAGEMENT LAYER     │  │          CONTAINER RUNTIME SECURITY LAB        │
│    (Docker Compose on Localhost)     │  │       (Kubernetes Cluster via kind: runtime)   │
├──────────────────────────────────────┤  ├────────────────────────────────────────────────┤
│                                      │  │  Namespace: dev         Namespace: staging     │
│   ┌──────────────────────────────┐   │  │  (Permissive / NOTICE)  (Moderate / WARNING)   │
│   │   OWASP DefectDojo Stack     │   │  │         │                          │           │
│   │   • Nginx (:8080, :9443 TLS) │   │  │         ▼                          ▼           │
│   │   • Django uWSGI Server      │   │  │     [nginx-dev]             [nginx-staging]    │
│   │   • Celery Worker & Beat     │   │  │         │                          │           │
│   │   • PostgreSQL & Valkey      │   │  │         └──────────────┬───────────┘           │
│   └──────────────▲───────────────┘   │  │                        │                       │
│                  │ REST API v2       │  │                        │                       │
│   ┌──────────────┴──────────────┐    │  │                        ▼                       │
│   │   Trivy Scanner (WSL2/Host) │    │  │  Namespace: prod (Strict / CRITICAL)           │
│   │   • Scans: nginx:alpine     │    │  │  (Tetragon In-Kernel Enforcement Active)       │
│   │   • Output: reports/*.json  │    │  │         │                                      │
│   └─────────────────────────────┘    │  │         ▼                                      │
│                                      │  │     [nginx-prod] (10.244.0.5:80 Healthy)       │
└──────────────────────────────────────┘  └─────────┬──────────────────────────────────────┘
                                                    │
                                      Kernel Syscalls & VFS Hooks
                                 (sys_execve, fd_install, sys_setresuid)
                                                    │
                   ┌────────────────────────────────┴────────────────────────────────┐
                   ▼                                                                 ▼
      Falco DaemonSet (eBPF)                                               Tetragon DaemonSet (eBPF)
    (Namespace: falco)                                                   (Namespace: kube-system)
                   │                                                                 │
                   ▼                                                                 ▼
     Namespace-Aware Rules                                                 Tetragon TracingPolicies
    • dev: NOTICE priority                                                • prod-block-shell (Sigkill -> 137)
    • staging: WARNING priority                                           • prod-protect-sensitive-files (Sigkill)
    • prod: CRITICAL priority                                             • prod-block-network-tools (Sigkill)
    • /etc/shadow access alert                                            • prod-privilege-escalation (Sigkill)
```

---

## 3. Directory Structure

```text
.
├── .github/
│   └── workflows/
│       └── ci.yml                # Automated eBPF KinD CI/CD regression test workflow
├── Makefile                      # One-command management for Linux / macOS / WSL2
├── .env.example                  # Template for DefectDojo API URL, credentials & TLS ports
├── .gitignore                    # Excludes secrets (.env, tokens), binaries, and raw JSON reports
│
├── docs/
│   ├── demo.tape                 # VHS recording specification to generate demo.gif
│   └── screenshots/              # Screenshots of DefectDojo & test output
│
├── defectdojo/
│   ├── README.md                 # DefectDojo architecture, Windows port fix & lifecycle guide
│   └── docker-compose.override.yml # Override resolving port conflicts (9443:8443)
│
├── trivy/
│   └── README.md                 # Trivy scanner manual, CVE findings & static vs runtime comparison
│
├── scripts/
│   ├── scan-images.sh            # Automated Trivy scanner (Bash / Linux / Docker fallback)
│   ├── scan-images.ps1           # Automated Trivy scanner (PowerShell)
│   └── import-trivy-findings.ps1 # DefectDojo REST API v2 importer (import, reimport, deduplication)
│
├── reports/
│   ├── .gitkeep                  # Preserves reports folder in repository
│   ├── runtime-security-report.md# Automated runtime security regression test report
│   └── trivy-nginx-report.json   # Machine-readable Trivy JSON vulnerability report
│
├── cluster/
│   └── kind-config.yaml          # KinD cluster manifest with eBPF & control-plane mounts
│
├── namespaces/
│   └── namespaces.yaml           # dev, staging, prod, and monitoring namespaces
│
├── workloads/
│   ├── dev.yaml                  # Dev nginx deployment
│   ├── staging.yaml              # Staging nginx deployment
│   ├── prod.yaml                 # Production nginx deployment
│   └── monitoring.yaml           # Utility workload (sec-test-runner) for in-cluster tests
│
├── falco/
│   ├── values.yaml               # Helm values configured for modern eBPF and rules
│   └── custom-rules.yaml         # Standalone custom Falco rules definition
│
├── tetragon/
│   ├── values.yaml               # Tetragon Helm values (export filters & debugfs mounts)
│   ├── policies/
│   │   ├── 01-prod-block-shell.yaml        # Prevents interactive shell execution in prod
│   │   ├── 02-prod-protect-sensitive-files.yaml # Blocks /etc/shadow and token access in prod
│   │   ├── 03-prod-block-network-tools.yaml# Blocks nc/netcat/socat in prod
│   │   └── 04-prod-privilege-escalation.yaml # Blocks su/sudo with credential telemetry
│   └── README.md                 # Deep-dive Tetragon architecture & policy manual
│
├── tests/
│   ├── run-runtime-security-tests.sh # Unified runtime regression suite (Bash / Linux / CI)
│   ├── run-runtime-security-tests.ps1 # Unified runtime regression suite (PowerShell)
│   ├── test-tetragon-enforcement.ps1 # Dedicated Tetragon verification (PowerShell)
│   └── run-all-tests.ps1         # Falco test runner (PowerShell)
│
└── README.md                     # Master documentation
```


---

## 4. Setup & Installation Guide

### Prerequisites
- **Docker** (Docker Engine on Linux, or Docker Desktop on Windows/macOS with WSL2)
- **kind** (v0.20+)
- **kubectl** (v1.28+)
- **helm** (v3.12+)

---

### Quick Start (Linux / macOS / WSL2 with Makefile)

```bash
# 1. Spin up KinD cluster with eBPF support
make cluster

# 2. Deploy namespaces and workloads
make deploy

# 3. Install Falco and Tetragon via Helm
make install-falco
make install-tetragon

# 4. Apply production TracingPolicies
make policies

# 5. Run automated runtime security tests
make test
```

---

### Manual Setup (Windows PowerShell / Cross-Platform)

#### Step 1: Cluster & Workloads Baseline
```powershell
# Create Kind cluster if not already present
kind create cluster --config cluster/kind-config.yaml

# Apply namespaces and workloads
kubectl apply -f namespaces/namespaces.yaml
kubectl apply -f workloads/
```

### Step 2: Install Falco (Detection Engine)
```powershell
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

helm upgrade --install falco falcosecurity/falco `
  --namespace falco `
  --create-namespace `
  -f falco/values.yaml
```

### Step 3: Install Tetragon (Enforcement Engine)
```powershell
# Ensure Kind node has bpffs mounted
docker exec runtime-security-lab-control-plane mount -t bpf bpf /sys/fs/bpf

# Add Cilium Helm repository
helm repo add cilium https://helm.cilium.io
helm repo update

# Install Tetragon DaemonSet (pinned to stable v1.7.1)
helm upgrade --install tetragon cilium/tetragon `
  --version 1.7.1 `
  --namespace kube-system `
  --set crds.installMethod=helm `
  -f tetragon/values.yaml

# Wait for Tetragon readiness
kubectl rollout status -n kube-system ds/tetragon --timeout=60s
```

### Step 4: Apply Tetragon TracingPolicies
```powershell
kubectl apply -f tetragon/policies/
kubectl get tracingpolicy
```

---

## 5. Tetragon TracingPolicies Overview

| Policy File | Target Kernel Hook | Scope | Action | Description |
| :--- | :--- | :--- | :--- | :--- |
| `01-prod-block-shell.yaml` | `sys_execve` (syscall) | `ns=prod, app=nginx` | `Sigkill` | Kills `/bin/sh`, `/bin/bash`, `/bin/ash`, `/bin/dash` on spawn attempt |
| `02-prod-protect-sensitive-files.yaml` | `fd_install` (VFS) | `ns=prod, app=nginx` | `Sigkill` | Intercepts file descriptor installation for `/etc/shadow`, `/etc/sudoers`, `/root/.ssh`, and `/var/run/secrets/...` |
| `03-prod-block-network-tools.yaml` | `sys_execve` (syscall) | `ns=prod, app=nginx` | `Sigkill` | Kills `nc`, `netcat`, `ncat`, `socat` while leaving ordinary HTTP port 80 traffic open |
| `04-prod-privilege-escalation.yaml` | `sys_execve` + `sys_setresuid` | `ns=prod, app=nginx` | `Sigkill` + `Post` | Kills `su`/`sudo` execution (`Sigkill`) and records credential transitions (`Post`) |

### WSL2 Kernel Compatibility Note
In Microsoft WSL2 Linux kernel 6.6 (`6.6.87.2-microsoft-standard-WSL2`), `CONFIG_BPF_KPROBE_OVERRIDE` is disabled in the standard build. Tetragon detects this at load time and rejects `action: Override` with `override validation failed: override action not supported on syscalls, bpf_override_return helper not available`. 

Therefore, **`Sigkill`** is the verified, supported kernel enforcement action. `Sigkill` stops violating processes synchronously at the kernel boundary before file bytes can be returned or subcommands can execute.

---

## 6. Automated Runtime Security Validation Suite (Phase 2)

The automated regression test suite is available in both **Bash** (Linux/macOS/CI) and **PowerShell** (Windows):

```bash
# Linux / macOS / CI:
./tests/run-runtime-security-tests.sh
```

```powershell
# Windows PowerShell:
.\tests\run-runtime-security-tests.ps1
```

### Running the PowerShell Suite
Run directly with default options (executes all regression tests, prints colored status indicators, and generates the detailed markdown report at `reports/runtime-security-report.md`):
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\tests\run-runtime-security-tests.ps1
```

Or pass a custom report path or verbose flag:
```powershell
.\tests\run-runtime-security-tests.ps1 -ReportPath "reports/custom-runtime-report.md" -VerboseLog
```

The script exits with code **0** when all required tests pass, and exits with a **non-zero code (1)** if any required test fails.

### What Each Test Demonstrates

| Test ID | Test Scenario | Mechanism & Target | Expected Behavior |
| :--- | :--- | :--- | :--- |
| **TEST-A** | **Dev Shell Execution** | `/bin/sh` in `dev` (`nginx-dev`) | Execution succeeds (`exit code 0`). Falco generates an alert with priority `NOTICE` (`Shell Spawned in Development Container`). |
| **TEST-B** | **Staging Shell Execution** | `/bin/sh` in `staging` (`nginx-staging`) | Execution succeeds (`exit code 0`). Falco generates an alert with priority `WARNING` (`Shell Spawned in Staging Container`). |
| **TEST-C** | **Production Shell Prevention** | `/bin/sh` in `prod` (`nginx-prod`) | Tetragon `prod-block-shell` intercepts `sys_execve` and sends synchronous `Sigkill`. Process creation is **prevented before user-space initialization** (`exit code 137`, 0 stdout). |
| **TEST-D1** | **Sensitive File Access: `/etc/shadow`** | Reading `/etc/shadow` in `prod` (`nginx-prod`) | Process creation succeeds (`head` process spawns), but Tetragon `prod-protect-sensitive-files` intercepts `fd_install` VFS operation with synchronous `Sigkill`. Process is **terminated upon open** before file I/O occurs (`exit code 137`, 0 bytes leaked). |
| **TEST-D2** | **Sensitive File Protection: Non-Existent Path** | Accessing `/etc/sudoers` in `prod` (`nginx-prod`) | Evaluates edge-case where a policy-protected path does not exist in the rootfs. Fails with `No such file or directory` (`exit code 1`, ENOENT). Differentiates file absence from active runtime enforcement and reports **`INCONCLUSIVE`** instead of false-positive enforcement. |
| **TEST-E** | **Normal Application Web Traffic** | HTTP port 80 request from `dev` to `prod` | Workload responds cleanly with `HTTP 200` ("Welcome to nginx!"). Proves that eBPF kprobes (`sys_execve`, `fd_install`) do not disrupt standard worker process execution or legitimate HTTP requests. |

### Interpreting Verdicts: PASS, FAIL, and INCONCLUSIVE

- **`PASS`**: The operation completed exactly as expected, verified by real execution results, process termination codes, and matching Falco/Tetragon telemetry.
  - For permissive environments (`dev`, `staging`), process completed with exit code 0 and triggered the expected Falco alert priority (`NOTICE`, `WARNING`).
  - For enforced environments (`prod`), the violating process was terminated synchronously by kernel `SIGKILL` (`exit code 137`), producing zero output and zero leaked data.
- **`FAIL`**: An unauthorized action was allowed to execute, or a policy did not trigger as required (e.g., shell in prod exiting with 0, Falco alert priority mismatch, sensitive data leaked, or exit code non-137). The suite returns exit code 1.
- **`INCONCLUSIVE`**: The test cannot definitively verify runtime enforcement because a precondition was not met (e.g., target file does not exist, command failed with `ENOENT` rather than `SIGKILL`). **Inconclusive tests are never reported as successful enforcement.**

### How to Inspect Falco Alerts

Inspect real-time Falco alerts emitted to container stdout:
```powershell
# Follow live alerts
kubectl logs -n falco -l app.kubernetes.io/name=falco -f

# View the last 20 alerts
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=20

# Filter for specific rule categories
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=50 | Select-String -Pattern "Shell spawned|Sensitive"
```

### How to Inspect Tetragon Enforcement Events

Tetragon provides both kernel daemon logs and JSON event streams:
```powershell
# 1. Inspect Tetragon daemon logs for policy lifecycle and sensor loading
kubectl logs -n kube-system ds/tetragon -c tetragon --tail=30

# 2. View compact real-time Tetragon event stream via tetra CLI
kubectl exec -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact --namespace prod

# 3. Inspect raw JSON event log exported by Tetragon
kubectl exec -n kube-system ds/tetragon -c tetragon -- tail -n 20 /var/run/cilium/tetragon/tetragon.log

# 4. Filter Tetragon events for specific processes or targets
kubectl exec -n kube-system ds/tetragon -c tetragon -- sh -c "cat /var/run/cilium/tetragon/tetragon.log | grep -E 'head|nginx-prod' | tail -n 5"
```

### Troubleshooting Failed Tests

1. **Test C Fails (Shell Allowed in Production / Exit Code 0)**:
   - Check if `prod-block-shell` TracingPolicy is applied: `kubectl get tracingpolicy`.
   - If missing, re-apply it: `kubectl apply -f tetragon/policies/01-prod-block-shell.yaml`.
   - Ensure Tetragon daemon loaded the policy: `kubectl logs -n kube-system ds/tetragon -c tetragon | Select-String "prod-block-shell"`.

2. **Test D Fails (Sensitive Data Leaked / Exit Code not 137)**:
   - Check if `prod-protect-sensitive-files` is active: `kubectl get tracingpolicy prod-protect-sensitive-files`.
   - Verify that the target file exists in the container (`/etc/shadow`). If checking missing paths (e.g. `/etc/sudoers`), the result should be `INCONCLUSIVE`.

3. **Missing or Delayed Falco Alerts**:
   - Verify Falco pod health: `kubectl get pods -n falco`.
   - Check if the modern eBPF driver is loaded: `kubectl logs -n falco -l app.kubernetes.io/name=falco | Select-String "eBPF"`.
   - Allow a 1.5-second buffer between test command execution and log polling to account for syscall buffer flushing.

4. **Tetragon DaemonSet Not Ready**:
   - Verify that `/sys/kernel/debug` and BTF are mounted on the node: `docker exec runtime-security-lab-control-plane ls -la /sys/kernel/btf/vmlinux`.
   - Verify BPF filesystem: `docker exec runtime-security-lab-control-plane mount | Select-String "bpf"`.

---

## 7. Additional Verification Suites

### Dedicated Tetragon Enforcement Suite
```powershell
.\tests\test-tetragon-enforcement.ps1
```

### Unified Falco Test Runner
```powershell
.\tests\run-all-tests.ps1
```

---

## 8. DefectDojo & Trivy Vulnerability Management (Phase 3)

### 8.1 Architecture & Separation of Concerns

Phase 3 integrates [OWASP DefectDojo](https://docs.defectdojo.com/) and [Aqua Security Trivy](https://trivy.dev/) for vulnerability management while maintaining absolute architectural separation from Kubernetes runtime security:

- **Host-Level Deployment**: DefectDojo runs via Docker Compose on the Windows host/WSL2 rather than inside the Kind cluster. This prevents resource starvation on the single-node Kind cluster and isolates vulnerability governance from workload lifecycles.
- **Strict Data Segregation**: Trivy provides static package CVE findings for container images (`nginx:alpine`). Falco and Tetragon generate real-time kernel telemetry. Raw runtime events are **never** forwarded directly to DefectDojo as vulnerability findings, preserving clarity and avoiding alert fatigue.
- **Persistent Storage**: DefectDojo findings, engagement history, and risk acceptance records are persisted in named Docker volumes (`defectdojo_postgres`, `defectdojo_media`, `defectdojo_redis`).

### 8.2 DefectDojo Deployment & Windows Port Configuration

On Windows hosts, Hyper-V dynamically reserves port range `8421 - 8520`. To avoid port collision with DefectDojo's default HTTPS port `8443`, the TLS port is remapped to `9443`:

```powershell
# Set TLS port and start DefectDojo stack (HTTP on 8080, HTTPS on 9443)
$env:DD_TLS_PORT = "9443"
docker compose -f "<path-to-DefectDojo>/docker-compose.yml" -f defectdojo/docker-compose.override.yml up -d

# Verify all services are healthy
docker ps --filter "name=django-defectdojo"
Invoke-WebRequest -Uri "http://localhost:8080/login" -UseBasicParsing | Select-Object StatusCode, StatusDescription
```

### 8.3 Authentication & Secrets Management

API credentials are kept strictly out of version control using `.env` (gitignored) and `.env.example`:

1. Copy `.env.example` to `.env`:
   ```powershell
   Copy-Item .env.example .env
   ```
2. Retrieve or generate the Django REST Framework API v2 token:
   ```powershell
   docker exec (docker ps -q --filter "name=uwsgi" | Select-Object -First 1) python manage.py drf_create_token admin
   ```
3. Set `DEFECTDOJO_API_TOKEN=<generated_token>` in `.env`.

### 8.4 Automated Vulnerability Scanning Workflow

#### Step 1: Scan Container Images with Trivy
Run the automated image scanner against the workloads in the lab:
```powershell
# Scan production/staging/dev nginx workload (nginx:alpine)
.\scripts\scan-images.ps1 -ImageName "nginx:alpine" -OutputPath "reports/trivy-nginx-report.json"

# Scan monitoring utility workload (alpine:latest)
.\scripts\scan-images.ps1 -ImageName "alpine:latest" -OutputPath "reports/trivy-alpine-report.json"
```
The script validates the generated JSON report and outputs a severity breakdown (e.g., 3 HIGH, 3 MEDIUM vulnerabilities for `nginx:alpine`).

#### Step 2: Import Findings into DefectDojo
Import the JSON report via DefectDojo REST API v2:
```powershell
.\scripts\import-trivy-findings.ps1 -ReportPath "reports/trivy-nginx-report.json"
```
The script automatically:
- Authenticates against `http://localhost:8080/api/v2/`.
- Ensures Product **"Kubernetes Runtime Security Lab"** exists with simple risk acceptance enabled.
- Ensures Engagement **"Container Image Vulnerability Scans"** exists.
- Ingests the findings into a new Test under the `Trivy Scan` parser.
- Outputs an inventory table of imported CVEs and severities.

#### Step 3: Demonstrate Re-import & Deduplication
DefectDojo deduplicates recurring findings across subsequent scans:
```powershell
.\scripts\import-trivy-findings.ps1 -ReportPath "reports/trivy-nginx-report.json" -Reimport
```
Output confirms:
- `Created: 0`
- `Closed: 0`
- `Untouched: 6`
- Zero duplicate entries created.

#### Step 4: Record Risk Acceptance & Track Remediation
Risk acceptance can be recorded through the DefectDojo UI or programmatically via the REST API:
```powershell
# Example: Accept risk on CVE-2026-85091 (Finding ID 41)
$headers = @{ "Authorization" = "Token $env:DEFECTDOJO_API_TOKEN"; "Content-Type" = "application/json" }
$body = @{ risk_accepted = $true; active = $false } | ConvertTo-Json
Invoke-RestMethod -Uri "http://localhost:8080/api/v2/findings/41/" -Method Patch -Headers $headers -Body $body
```
Re-running `.\scripts\import-trivy-findings.ps1 -Reimport` preserves the `RiskAccepted: True` state without reactivating or overwriting the accepted risk.

---

## 9. Rollback Procedures

### Disable Tetragon Enforcement
To remove runtime enforcement while keeping Falco detection operational:
```powershell
kubectl delete -f tetragon/policies/
kubectl get tracingpolicy
```

### Complete Tetragon Uninstallation
```powershell
helm uninstall tetragon -n kube-system
```
*Falco, workloads, and cluster networking remain unaffected.*

### DefectDojo Teardown
```powershell
# Stop DefectDojo containers while preserving database volume
docker compose -f "<path-to-DefectDojo>/docker-compose.yml" stop

# Complete teardown of DefectDojo stack (preserves volumes)
docker compose -f "<path-to-DefectDojo>/docker-compose.yml" down
```

