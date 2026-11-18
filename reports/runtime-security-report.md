# Kubernetes Runtime Security Automated Validation Report

**Generated:** 2026-10-12 08:12:06 UTC  
**Cluster:** runtime-security-lab  
**Host Kernel:** 6.6.87.2-microsoft-standard-WSL2  
**Kubernetes Version:** v1.31.2  

---

## 1. Executive Summary

| Metric | Value | Status |
| :--- | :--- | :--- |
| **Total Tests Executed** | 6 | - |
| **Required Security Tests Passed** | 5 | Operational |
| **Tests Failed** | 0 | Zero Failures |
| **Inconclusive Edge-Cases** | 1 | Identified (Documented Below) |

---

## 2. Test Execution Matrix

| Test ID | Test Name | Target Namespace | Target Workload | Expected Outcome | Actual Outcome | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **TEST-A** | Dev Shell Execution & Falco Detection | `dev` | `nginx-dev-5f4fc66c46-qgtmz` | Execution succeeds (ExitCode 0); Falco alert collected with priority NOTICE | ExitCode 0; Output: 'dev_shell_validation_875733901'; Falco Priority: NOTICE | **PASS** |
| **TEST-B** | Staging Shell Execution & Falco Detection | `staging` | `nginx-staging-5b489cbd5b-hwq5d` | Execution follows staging policy (ExitCode 0); Falco alert collected with priority WARNING | ExitCode 0; Output: 'staging_shell_validation_2083098318'; Falco Priority: WARNING | **PASS** |
| **TEST-C** | Production Shell Prevention (Tetragon In-Kernel Enforcement) | `prod` | `nginx-prod-7c486fb578-tqxjj` | Operation is denied / process terminated by Tetragon Sigkill before execution begins (ExitCode 137) | ExitCode 137; Stderr: 'command terminated with exit code 137'; User Output: None | **PASS** |
| **TEST-D1** | Sensitive File Access: /etc/shadow in Production | `prod` | `nginx-prod-7c486fb578-tqxjj` | Process terminated by Tetragon Sigkill on fd_install; 0 sensitive file bytes leaked (ExitCode 137) | ExitCode 137; Sensitive Contents Suppressed/Zero Leaked; Result: Process creation succeeded (head spawned), but process was terminated upon fd_install when linking /etc/shadow file descriptor. 0 bytes of sensitive data exposed. | **PASS** |
| **TEST-D2** | Sensitive File Protection: Non-Existent Protected Path (/etc/sudoers) | `prod` | `nginx-prod-7c486fb578-tqxjj` | Report INCONCLUSIVE if target file does not exist to avoid false-positive enforcement claims | ExitCode 1; Output: 'head: /etc/sudoers: No such file or directory command terminated with exit code 1' | **INCONCLUSIVE** |
| **TEST-E** | Normal Application Web Traffic Preservation | `prod` | `nginx-prod-7c486fb578-tqxjj` | HTTP requests to Nginx production workload succeed with HTTP 200 / 'Welcome to nginx!' | ExitCode 0; HTTP Response contains 'Welcome to nginx!' | **PASS** |

---

## 3. Detailed Evidence & Telemetry Findings

### TEST-A: Dev Shell Execution & Falco Detection
- **Status:** PASS
- **Namespace:** `dev`
- **Workload:** `nginx-dev-5f4fc66c46-qgtmz`
- **Enforcement / Detection Rule:** Falco Rule: 'Shell Spawned in Development Container' (Priority: NOTICE)
- **Expected Outcome:** Execution succeeds (ExitCode 0); Falco alert collected with priority NOTICE
- **Observed Outcome:** ExitCode 0; Output: 'dev_shell_validation_875733901'; Falco Priority: NOTICE
- **Technical Evidence:**
  ```text
  2026-10-12T08:11:58.382939529+0000: Notice NOTICE: Shell spawned in dev container for development/testing (user=root ns=dev pod=nginx-dev-5f4fc66c46-qgtmz container=nginx process=sh cmdline=sh -c echo dev_shell_validation_875733901) container_id=57c9b487f1ca container_name=nginx container_image_repository=docker.io/library/nginx container_image_tag=alpine k8s_pod_name=nginx-dev-5f4fc66c46-qgtmz k8s_ns_name=dev
  ```
- **Analysis & Notes:** Development environment permits interactive shells for developer testing while generating low-severity NOTICE telemetry.

### TEST-B: Staging Shell Execution & Falco Detection
- **Status:** PASS
- **Namespace:** `staging`
- **Workload:** `nginx-staging-5b489cbd5b-hwq5d`
- **Enforcement / Detection Rule:** Falco Rule: 'Shell Spawned in Staging Container' (Priority: WARNING)
- **Expected Outcome:** Execution follows staging policy (ExitCode 0); Falco alert collected with priority WARNING
- **Observed Outcome:** ExitCode 0; Output: 'staging_shell_validation_2083098318'; Falco Priority: WARNING
- **Technical Evidence:**
  ```text
  2026-10-12T08:12:00.613191522+0000: Warning WARNING: Shell spawned in staging container (user=root ns=staging pod=nginx-staging-5b489cbd5b-hwq5d container=nginx process=sh cmdline=sh -c echo staging_shell_validation_2083098318) container_id=2b1fb955f0b7 container_name=nginx container_image_repository=docker.io/library/nginx container_image_tag=alpine k8s_pod_name=nginx-staging-5b489cbd5b-hwq5d k8s_ns_name=staging
  ```
- **Analysis & Notes:** Staging environment observes pre-production workloads with WARNING priority to detect unexpected interactive administrative activity.

### TEST-C: Production Shell Prevention (Tetragon In-Kernel Enforcement)
- **Status:** PASS
- **Namespace:** `prod`
- **Workload:** `nginx-prod-7c486fb578-tqxjj`
- **Enforcement / Detection Rule:** Tetragon TracingPolicy: 'prod-block-shell' (sys_execve -> Sigkill)
- **Expected Outcome:** Operation is denied / process terminated by Tetragon Sigkill before execution begins (ExitCode 137)
- **Observed Outcome:** ExitCode 137; Stderr: 'command terminated with exit code 137'; User Output: None
- **Technical Evidence:**
  ```text
  Kernel Action: SIGKILL (ExitCode 137); Hook: sys_execve (sys_execve -> Sigkill); Mechanism: Process creation prevented at sys_execve boundary; synchronous SIGKILL dispatched before entry to userspace.
  ```
- **Analysis & Notes:** Kernel-level enforcement intercepts sys_execve. Process creation is terminated synchronously before bash/sh user-space initialization.

### TEST-D1: Sensitive File Access: /etc/shadow in Production
- **Status:** PASS
- **Namespace:** `prod`
- **Workload:** `nginx-prod-7c486fb578-tqxjj`
- **Enforcement / Detection Rule:** Tetragon TracingPolicy: 'prod-protect-sensitive-files' (fd_install -> Sigkill)
- **Expected Outcome:** Process terminated by Tetragon Sigkill on fd_install; 0 sensitive file bytes leaked (ExitCode 137)
- **Observed Outcome:** ExitCode 137; Sensitive Contents Suppressed/Zero Leaked; Result: Process creation succeeded (head spawned), but process was terminated upon fd_install when linking /etc/shadow file descriptor. 0 bytes of sensitive data exposed.
- **Technical Evidence:**
  ```text
  Kernel Action: SIGKILL (ExitCode 137, 0 data leaked); Hook: fd_install on /etc/shadow; Falco Alert: 2026-10-12T08:12:03.624324817+0000: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=<NA> ggparent=<NA> gggparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=head proc_exepath=/bin/busybox parent=containerd-shim command=head -n 1 /etc/shadow terminal=0 container_id=6b22ea9d3737 container_name=nginx container_image_repository=docker.io/library/nginx container_image_tag=alpine k8s_pod_name=nginx-prod-7c486fb578-tqxjj k8s_ns_name=prod
  ```
- **Analysis & Notes:** Demonstrates VFS-layer enforcement: 'head' process begins execution, but fd_install intercepts the file descriptor before read operations begin.

### TEST-D2: Sensitive File Protection: Non-Existent Protected Path (/etc/sudoers)
- **Status:** INCONCLUSIVE
- **Namespace:** `prod`
- **Workload:** `nginx-prod-7c486fb578-tqxjj`
- **Enforcement / Detection Rule:** Tetragon TracingPolicy: 'prod-protect-sensitive-files' (Path: /etc/sudoers)
- **Expected Outcome:** Report INCONCLUSIVE if target file does not exist to avoid false-positive enforcement claims
- **Observed Outcome:** ExitCode 1; Output: 'head: /etc/sudoers: No such file or directory command terminated with exit code 1'
- **Technical Evidence:**
  ```text
  Kernel ENOENT return (No such file or directory) preceded fd_install interception
  ```
- **Analysis & Notes:** File /etc/sudoers is defined in policy prefix list but does not exist in the container filesystem. Operation failed due to ENOENT (file absence), not active Tetragon enforcement.

### TEST-E: Normal Application Web Traffic Preservation
- **Status:** PASS
- **Namespace:** `prod`
- **Workload:** `nginx-prod-7c486fb578-tqxjj`
- **Enforcement / Detection Rule:** Operational Baseline (Runtime Enforcement Non-Interference)
- **Expected Outcome:** HTTP requests to Nginx production workload succeed with HTTP 200 / 'Welcome to nginx!'
- **Observed Outcome:** ExitCode 0; HTTP Response contains 'Welcome to nginx!'
- **Technical Evidence:**
  ```text
  HTTP probe to http://10.244.0.5 served valid response without container termination
  ```
- **Analysis & Notes:** Confirms that eBPF kprobes (sys_execve and fd_install) do not disrupt standard worker process execution or network request handling.

---

## 4. Inconclusive Tests & Edge-Case Analysis

The suite rigorously differentiates genuine runtime prevention from coincidental command failure. The following tests were marked **INCONCLUSIVE**:

### TEST-D2: Sensitive File Protection: Non-Existent Protected Path (/etc/sudoers)
- **Reason:** File /etc/sudoers is defined in policy prefix list but does not exist in the container filesystem. Operation failed due to ENOENT (file absence), not active Tetragon enforcement.
- **Evidence:** `Kernel ENOENT return (No such file or directory) preceded fd_install interception`
- **Security Guidance:** Ensure that paths protected by TracingPolicies exist within target containers if active enforcement is expected to be validated, or treat non-existent paths as static containment.

---

## 5. Troubleshooting & Remediation Notes

### Falco Event Delays or Missing Alerts
1. **Check Falco Pod Health**: Ensure `falco` DaemonSet in namespace `falco` is 1/1 Ready (`kubectl get ds -n falco`).
2. **Inspect Falco Driver Status**: Verify modern eBPF driver initialization via `kubectl logs -n falco -l app.kubernetes.io/name=falco | grep eBPF`.
3. **Rate Limiting & Syscall Filters**: Some rapid repeated commands may encounter syscall throttling or drop counters. Ensure test runner sleeps 1.5s between executions.

### Tetragon In-Kernel Enforcement Failures
1. **Confirm TracingPolicies**: Check active policies via `kubectl get tracingpolicy`. If `prod-block-shell` is missing, re-apply it: `kubectl apply -f tetragon/policies/01-prod-block-shell.yaml`.
2. **Verify Process Termination vs Creation Prevention**:
   - `sys_execve` hook (`prod-block-shell`): Dispatches synchronous `SIGKILL` at syscall entry, producing exit code 137 with zero stdout.
   - `fd_install` hook (`prod-protect-sensitive-files`): Allows process spawning, but dispatches synchronous `SIGKILL` upon attempting to open protected file descriptors.
3. **WSL2 / Linux Kernel BTF Compatibility**: Verify BTF information is mounted at `/sys/kernel/debug` and `/sys/kernel/btf/vmlinux` inside the Tetragon container.

---

*Report generated by tests/run-runtime-security-tests.ps1*
