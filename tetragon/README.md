# Cilium Tetragon Runtime Security & Enforcement Lab

This directory contains the Helm configuration, TracingPolicies, and operational documentation for **Cilium Tetragon** runtime enforcement in the Kubernetes Runtime Security Lab (`runtime-security-lab`).

---

## 1. Falco vs. Tetragon: Detection vs. Prevention

In modern Kubernetes container security, runtime defense requires both **real-time visibility/auditing** and **active kernel-level mitigation**:

| Capability | Falco (Detection & Alerting) | Tetragon (Prevention & Enforcement) |
| :--- | :--- | :--- |
| **Primary Role** | Runtime behavioral surveillance, anomaly detection, audit trail | Synchronous in-kernel policy enforcement, process killing, activity interception |
| **Driver Engine** | Modern eBPF probe / Syscall tracepoint rings | Cilium Tetragon eBPF sensors (kprobes, generic kprobes, fentry/tracepoints) |
| **Response Model** | **Passive**: Emits alerts to stdout, syslog, Falcosidekick, or SIEM | **Active**: Intercepts syscalls directly inside kernel space via `Sigkill` |
| **Impact on Attacker** | Actions are recorded for incident response, but commands execute unless an external orchestrator kills the pod | Process is terminated **synchronously** in the kernel (`exit code 137`) before damage or exfiltration occurs |
| **Best Used For** | Broad cluster-wide reconnaissance, baseline anomaly analysis, regulatory compliance auditing | High-criticality production workloads where unauthorized actions must be stopped immediately |

> **Defense-in-Depth Synergy**: Falco generates alert telemetry and contextual event trails, while Tetragon stops attacker commands at the Linux system call layer.

---

## 2. Architecture & Coexistence

```text
                               Kubernetes Cluster: runtime-security-lab
                                                  │
                 ┌────────────────────────────────┼────────────────────────────────┐
                 │                                │                                │
           Namespace: dev                 Namespace: staging               Namespace: prod
          (security.lab/env: dev)       (security.lab/env: staging)       (security.lab/env: prod)
                 │                                │                                │
            [nginx-dev]                     [nginx-staging]                   [nginx-prod]
          (Allowed testing)               (Staging telemetry)            (Enforced Restrictions)
                 │                                │                                │
                 └────────────────────────────────┼────────────────────────────────┘
                                                  │
                                          Linux Kernel 6.6
                                   (WSL2: 6.6.87.2-microsoft-standard)
                                                  │
                       ┌──────────────────────────┴──────────────────────────┐
                       │                                                     │
                       ▼                                                     ▼
              Falco Sensor (eBPF)                                  Tetragon Sensor (eBPF)
           DaemonSet: falco/falco                               DaemonSet: kube-system/tetragon
                       │                                                     │
                       ▼                                                     ▼
          Detection & Alerting                                  In-Kernel Enforcement
        - Shell Spawned (CRITICAL)                            - Terminate Shell (Sigkill)
        - Token Read (CRITICAL)                               - Terminate Credential Read (Sigkill)
        - Privilege Esc (ERROR)                               - Terminate Netcat / Su (Sigkill)
                       │                                                     │
                       ▼                                                     ▼
               Falco Log Stream                                    Exit Code 137 (SIGKILL)
             (Security Telemetry)                               (Blocked with 0 Data Leaked)
```

Both agents hook into the host Linux kernel eBPF subsystem concurrently without interference:
- Falco captures tracepoints to assemble human-readable syslog alerts.
- Tetragon evaluates TracingPolicies in the kernel and applies synchronous `Sigkill` actions.

---

## 3. Directory Layout

```text
tetragon/
├── values.yaml                         # Tetragon Helm chart configuration
├── policies/
│   ├── 01-prod-block-shell.yaml        # Prevents interactive shells (/bin/sh, etc.) in prod
│   ├── 02-prod-protect-sensitive-files.yaml # Blocks /etc/shadow and k8s token access in prod
│   ├── 03-prod-block-network-tools.yaml# Prevents nc/netcat utilities in prod
│   └── 04-prod-privilege-escalation.yaml # Prevents su/sudo execution with credential telemetry
└── README.md                           # Architecture, policy documentation, and rollback guide
```

---

## 4. TracingPolicy Reference

### Policy 1: `01-prod-block-shell.yaml`
- **Hook Point**: `sys_execve` (system call kprobe).
- **Target Workload**: Scoped via `podSelector` to `app: nginx` in namespace `prod` (`k8s:io.kubernetes.pod.namespace: In [prod]`).
- **Enforcement Action**: `Sigkill`.
- **Target Paths**: `/bin/sh`, `/bin/bash`, `/bin/ash`, `/bin/dash`, `/usr/bin/sh`, `/usr/bin/bash`, `/usr/bin/ash`, `/usr/bin/dash`.
- **Observed Behavior**:
  - `dev` & `staging`: `/bin/sh` executes normally (returns exit code 0).
  - `prod`: Process receives `SIGKILL` on the `sys_execve` call (exit code 137), producing 0 stdout.
- **Distinction**: Process is terminated at the kernel execution boundary before entering user-space execution.
- **False-Positive Risk**: Low for minimal containerized microservices. If maintenance is required, ephemeral debug containers or separate admin namespaces should be used.

### Policy 2: `02-prod-protect-sensitive-files.yaml`
- **Hook Point**: `fd_install` (kernel VFS function).
- **Target Workload**: Scoped to `prod` namespace `app: nginx`.
- **Enforcement Action**: `Sigkill`.
- **Target Paths**:
  - `/etc/shadow`
  - `/etc/sudoers`
  - `/root/.ssh`
  - `/run/secrets/kubernetes.io/serviceaccount`
  - `/var/run/secrets/kubernetes.io/serviceaccount`
- **Observed Behavior**:
  - `dev`: `head -n 1 /etc/shadow` executes cleanly.
  - `prod`: Any binary attempting to install a file descriptor pointing to these paths is instantly terminated (`exit code 137`) before read operations begin.
- **Path Resolution Nuance**: In modern Linux and Kubernetes distributions, `/var/run` is a symlink to `/run`. Because `fd_install` inspects the resolved `struct file*`, matching both `/run/secrets/...` and `/var/run/secrets/...` prevents symlink bypasses.

### Policy 3: `03-prod-block-network-tools.yaml`
- **Hook Point**: `sys_execve` (system call kprobe).
- **Target Workload**: Scoped to `prod` namespace `app: nginx`.
- **Enforcement Action**: `Sigkill`.
- **Target Utilities**: `/nc`, `/netcat`, `/ncat`, `/socat` (matched via Postfix and absolute paths).
- **Observed Behavior**:
  - `dev`: `nc` executes and displays usage.
  - `prod`: `nc` terminates with exit code 137.
  - Normal web traffic: Inbound HTTP traffic to Nginx (`GET /`) is completely unaffected and continues serving HTTP 200 responses.

### Policy 4: `04-prod-privilege-escalation.yaml`
- **Hook Point 1 (Enforcement)**: `sys_execve` targeting `/su`, `/sudo`, `/pkexec`, `/doas` with `Sigkill`.
- **Hook Point 2 (Observability)**: `sys_setresuid` system call with action `Post` to capture telemetry on UID/GID transitions.
- **Target Workload**: Scoped to `prod` namespace `app: nginx`.
- **Observed Behavior**:
  - `dev`: `su -c "id"` executes and resolves `uid=0`.
  - `prod`: `su` receives `SIGKILL` on invocation (`exit code 137`).
- **Rationale for Split**: Killing all processes on `setresuid` can break normal unprivileged daemon child forks. Splitting binary invocation blocking (`Sigkill`) from credential change telemetry (`Post`) provides protection without destabilizing container processes.

---

## 5. Kernel, eBPF, & WSL2 Environment Analysis

| Subsystem / Feature | Lab Status | Technical Impact |
| :--- | :--- | :--- |
| **Linux Kernel** | `6.6.87.2-microsoft-standard-WSL2` | Modern long-term stable kernel supporting eBPF ring buffers and generic kprobes |
| **BPF Type Format (BTF)** | Native (`/sys/kernel/btf/vmlinux`, 6.05 MB) | Tetragon operates with full CO-RE (Compile-Once Run-Everywhere) support without external headers |
| **BPF Filesystem** | Mounted at `/sys/fs/bpf` | Tetragon pins BPF maps (`execve_map`, `tcpmon_map`, etc.) |
| **Debugfs & Tracefs** | Mounted at `/sys/kernel/debug` and `/sys/kernel/tracing` | Kernel tracepoints and kprobe events are accessible |
| **`CONFIG_BPF_KPROBE_OVERRIDE`** | **Not enabled** in standard WSL2 kernel | **Important Limitation**: `action: Override` (returning synthetic `-EPERM` without killing process) requires `bpf_override_return`, which is unavailable on WSL2. Tetragon logs `override validation failed: override action not supported on syscalls, bpf_override_return helper not available`. |
| **Enforcement Mechanism** | `action: Sigkill` | Fully supported and functional. Provides hard termination of violating processes at the kernel boundary. |

---

## 6. Installation & Deployment Guide

### Prerequisites
Run the following in Windows PowerShell from the repository root:

```powershell
# 1. Ensure Kind node has bpffs mounted
docker exec runtime-security-lab-control-plane mount -t bpf bpf /sys/fs/bpf

# 2. Add and update Cilium Helm repository
helm repo add cilium https://helm.cilium.io
helm repo update

# 3. Install Tetragon DaemonSet into kube-system
helm upgrade --install tetragon cilium/tetragon `
  --namespace kube-system `
  -f tetragon/values.yaml

# 4. Wait for DaemonSet readiness
kubectl rollout status -n kube-system ds/tetragon --timeout=60s

# 5. Apply the production TracingPolicies
kubectl apply -f tetragon/policies/
```

### Verification Commands
```powershell
# Check installed TracingPolicies
kubectl get tracingpolicy

# Verify Tetragon pod is Ready (2/2)
kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon

# Test Tetragon tetra CLI
kubectl exec -n kube-system ds/tetragon -c tetragon -- tetra version
```

---

## 7. Running the Automated Verification Suite

Execute the dedicated PowerShell test runner:

```powershell
.\tests\test-tetragon-enforcement.ps1
```

The test runner validates:
1. Cluster and Tetragon DaemonSet readiness.
2. All 4 TracingPolicies are active in the cluster.
3. Permissive execution in `dev` and `staging`.
4. Hard prevention via SIGKILL (exit code 137) in `prod`.
5. Preservation of normal HTTP web server traffic in `prod`.
6. Simultaneous Falco alert generation.

---

## 8. Rollback & Uninstallation Procedures

### A. Remove an Individual Policy
To roll back a single enforcement policy without affecting others:
```powershell
# Example: Remove shell blocking policy
kubectl delete -f tetragon/policies/01-prod-block-shell.yaml

# Verify removal
kubectl get tracingpolicy
```

### B. Disable All Tetragon Enforcement (Observability Only)
To remove all preventive enforcement while keeping Falco detection active:
```powershell
# Delete all active tracing policies
kubectl delete -f tetragon/policies/

# Confirm no policies remain
kubectl get tracingpolicy
```
*Result: Falco continues detecting events; workloads are no longer terminated.*

### C. Complete Uninstallation of Tetragon
To completely remove Tetragon from the cluster:
```powershell
# Uninstall the Tetragon Helm release
helm uninstall tetragon -n kube-system

# Verify removal
kubectl get ds -n kube-system tetragon
kubectl get crd | Select-String "cilium"
```
*Result: The Kind cluster, workloads in `dev`/`staging`/`prod`, and the Falco DaemonSet remain completely intact and operational.*
