# DefectDojo Integration Guide

## 1. Overview & Architecture

[OWASP DefectDojo](https://docs.defectdojo.com/) is an open-source vulnerability management platform that centralizes, deduplicates, and tracks findings from security scanners such as Trivy.

### Why Deploy via Docker Compose on Host (Outside the Kind Cluster)?

In this project, DefectDojo is maintained outside the `runtime-security-lab` Kubernetes cluster using official Docker Compose:

1. **Resource Preservation:** DefectDojo comprises six microservices (Nginx reverse proxy, Django uWSGI web server, Celery asynchronous workers, Celery beat scheduler, PostgreSQL database, and Valkey/Redis cache). Running these inside a single-node Kind cluster on Windows/WSL2 consumes excessive memory and CPU away from the Kubernetes runtime security lab.
2. **Lifecycle Independence:** Vulnerability tracking and security governance must remain accessible regardless of whether test workloads in `dev`, `staging`, or `prod` namespaces are being deployed, restarted, or torn down.
3. **Clean Runtime Audit Trails:** Keeping the DefectDojo stack outside the cluster ensures that Falco and Tetragon eBPF kernel monitors remain strictly dedicated to analyzing test container workloads without generating extraneous audit noise from Celery task workers or database transactions.

---

## 2. Storage & Security Model

- **Persistent Volumes:** Data durability is guaranteed across container restarts through named Docker volumes:
  - `defectdojo_postgres`: Stores the PostgreSQL database (products, engagements, tests, findings, risk acceptance states).
  - `defectdojo_media`: Stores uploaded report attachments and scan artifacts.
  - `defectdojo_redis`: Retains cache and task queue states.
- **Access Boundary:** Services bind exclusively to localhost (`127.0.0.1:8080`). No public ingress or external port forwarding is configured.
- **Authentication:** DefectDojo enforces Django authentication for the UI and Django REST Framework (DRF) HTTP header token authentication (`Authorization: Token <api_token>`) for automated scan ingestion.

---

## 3. Windows Hyper-V Port Exclusion Resolution

On Windows 10/11 with Hyper-V or WSL2 enabled, the OS dynamically reserves specific port ranges (frequently `8421 - 8520`) for internal networking. You can verify this by running:
```powershell
netsh interface ipv4 show excludedportrange protocol=tcp
```

Because DefectDojo's default HTTPS port is `8443`, starting the stack on Windows without overriding this port fails with:
`Error response from daemon: ports are not available: exposing port TCP 0.0.0.0:8443 -> 127.0.0.1:0: /forwards/expose returned unexpected status: 500`

### Solution
Set `DD_TLS_PORT=9443` in your environment or compose configuration. Port `8080` (HTTP) and `9443` (HTTPS) avoid all reserved ranges and bind cleanly.

---

## 4. PowerShell Lifecycle Commands

All commands below are designed to be run from Windows PowerShell.

### 4.1 Startup
If using the official DefectDojo repository directory (e.g., cloned at `$env:USERPROFILE\appsec-capstone-app\django-DefectDojo` or in WSL):

```powershell
# Set TLS port to bypass Windows Hyper-V port exclusion
$env:DD_TLS_PORT = "9443"

# Start DefectDojo in detached mode
docker compose -f "<path-to-DefectDojo>/docker-compose.yml" up -d
```

### 4.2 Health Check & UI Access
Verify all containers are running and healthy:

```powershell
docker ps --filter "name=django-defectdojo"
Invoke-WebRequest -Uri "http://localhost:8080/login" -UseBasicParsing | Select-Object StatusCode, StatusDescription
```

Access the web interface at: [http://localhost:8080](http://localhost:8080)

### 4.3 Retrieving Credentials & API Tokens

#### Retrieve Initial Admin Password
```powershell
# Read from the initializer container logs
docker logs (docker ps -a -q --filter "name=initializer" | Select-Object -First 1) | Select-String "Admin password:"
```

#### Generate / Retrieve API v2 Token
DefectDojo generates DRF API tokens for programmatic integration:

```powershell
docker exec (docker ps -q --filter "name=uwsgi" | Select-Object -First 1) python manage.py drf_create_token admin
```

Alternatively, log into the web UI at `http://localhost:8080`, click your user avatar in the top right, select **API v2 Key**, and copy the token.

Store this token in your local `.env` file as `DEFECTDOJO_API_TOKEN`.

### 4.4 Shutdown & Restart

```powershell
# Stop running containers while preserving data volumes
docker compose -f "<path-to-DefectDojo>/docker-compose.yml" stop

# Restart stopped containers
docker compose -f "<path-to-DefectDojo>/docker-compose.yml" start
```

### 4.5 Teardown & Cleanup (Caution)

```powershell
# Tear down containers (keeps persistent volumes intact)
docker compose -f "<path-to-DefectDojo>/docker-compose.yml" down

# WARNING: To completely erase all database records and volumes:
# docker compose -f "<path-to-DefectDojo>/docker-compose.yml" down -v
```
