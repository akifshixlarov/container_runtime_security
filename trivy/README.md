# Trivy Vulnerability Scanning

## 1. Role in the Security Architecture

[Aqua Security Trivy](https://trivy.dev/) is an open-source security scanner that detects vulnerabilities (CVEs), secrets, and software bill of materials (SBOM) in container images, filesystems, and Git repositories.

In this project, Trivy functions strictly as an automated **static vulnerability finding generator** for DefectDojo. It does not replace or interfere with Kubernetes runtime security.

---

## 2. Static Vulnerability Scanning vs. Runtime Security

A critical design requirement is maintaining clear boundaries between vulnerability management and kernel-level runtime protection:

| Dimension | Static Vulnerability Scanning (Trivy + DefectDojo) | Runtime Detection (Falco) | Runtime Enforcement (Tetragon) |
| :--- | :--- | :--- | :--- |
| **Lifecycle Phase** | Build, CI/CD, Pre-deployment & Registry Scanning | Container Execution (Post-deployment) | Container Execution (In-kernel) |
| **Observation Target** | Image layers, installed package versions, OS libraries (e.g. `apk`, `dpkg`) | Linux system calls, process lineage, file descriptors | eBPF kprobes, tracepoints, VFS file install (`fd_install`) |
| **Outcome** | Machine-readable CVE list, CVSS scores, remediation recommendations | Security alerts & log streams (NOTICE, WARNING, CRITICAL) | Synchronous process termination (`SIGKILL` / Exit 137) |
| **Storage / System** | Ingested into DefectDojo for tracking, deduplication, and risk acceptance | Log aggregators, SIEM, Falcosidekick | Kernel audit logs (`/var/run/cilium/tetragon/tetragon.log`) |
| **Limitations** | Cannot detect zero-days, runtime memory exploits, or policy deviations | Cannot block actions natively; post-execution alert only | Does not fix known vulnerable packages in underlying container images |

---

## 3. Workload Images & Scanner Output

The Kubernetes runtime lab runs `nginx:alpine` across `dev`, `staging`, and `prod` namespaces (`workloads/*.yaml`).

### Discovered Vulnerabilities
Scanning the actual `nginx:alpine` image used by the lab produces genuine, reproducible vulnerability records from the official Alpine Security Database:
- **CVE-2026-103111** (`pcre2` 10.48-r0) — Out-of-bounds write via crafted regular expression (**HIGH**, CVSS 7.6)
- **CVE-2026-4775** (`tiff` 4.7.1-r0) — Arbitrary code execution or denial of service via signed integer overflow (**HIGH**, CVSS 7.8)
- **CVE-2026-93990** (`libexpat` 2.8.4-r0) — Buffer overflow in XML parser (**HIGH**)
- **CVE-2026-85091** (`zlib` 1.3.2-r0) — Heap buffer overflow in `gz_vacate()` (**MEDIUM**)
- **CVE-2026-46675** (`libpng` 1.6.58-r1) — Memory corruption in PNG processing (**MEDIUM**)
- **CVE-2026-58055** (`nghttp2-libs` 1.69.0-r0) — Denial of service in HTTP/2 framing (**MEDIUM**)

All findings are documented directly from scanner output without fabrication or alteration.

---

## 4. Execution Workflow

The automated PowerShell script `scripts/scan-images.ps1` executes Trivy using the best available local runtime:

1. **Native Windows (`trivy.exe`):** If installed on the system PATH.
2. **WSL2 (`wsl trivy`):** Uses the Linux-native Trivy binary and cached vulnerability database.
3. **Docker Container (`aquasec/trivy`):** Fallback containerized execution if no local binary exists.

### Example Commands

```powershell
# Scan the default nginx:alpine workload image and output JSON
.\scripts\scan-images.ps1

# Scan a custom image with specific output destination
.\scripts\scan-images.ps1 -ImageName "nginx:alpine" -OutputPath "reports/trivy-nginx-report.json"
```

The resulting file `reports/trivy-nginx-report.json` adheres to Trivy JSON schema v2, which DefectDojo parses using its native `Trivy Scan` importer.
