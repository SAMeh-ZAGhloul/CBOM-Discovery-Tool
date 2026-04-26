# CBOM Discovery Tool

A complete Cryptographic Bill of Materials (CBOM) discovery toolkit using **Zeek** network monitoring, **Python** analysis, and an **HTML** dashboard. Includes three sample infrastructure applications for testing crypto discovery.

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                        CBOM DISCOVERY STACK                    │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │   Zeek       │    │   Python     │    │   HTML       │      │
│  │   Monitor    │───▶│   Analyzer   │───▶│   Dashboard  │      │
│  │              │    │              │    │              │      │
│  │ • Network    │    │ • Parse logs │    │ • Real-time  │      │
│  │   capture    │    │ • Build CBOM │    │   metrics    │      │
│  │ • Crypto     │    │ • Risk score │    │ • Findings   │      │
│  │   detection  │    │ • Alerts     │    │ • Export     │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
│         │                   ▲                   ▲              │
│         │                   │                   │              │
│         └───────────────────┴───────────────────               │
│                      Shared Volumes                            │
│              /shared/logs  →  /shared/cbom                     │
├────────────────────────────────────────────────────────────────┤
│                        SAMPLE APPLICATIONS                     │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │  Web App    │  │  SSH        │  │  Database               │ │
│  │  (HTTPS)    │  │  Service    │  │  (PostgreSQL+TLS)       │ │
│  │             │  │             │  │                         │ │
│  │ • TLS 1.2+  │  │ • RSA/ECDSA │  │ • TLS 1.2/1.3           │ │
│  │ • AES-256   │  │ • ED25519   │  │ • SCRAM-SHA-256         │ │
│  │ • ECDHE     │  │ • AES-CTR   │  │ • RSA Certs             │ │
│  │ • RSA 2048  │  │ • Curve25519│  │ • AES-GCM               │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
│       :8443            :2222                :5432              │
└────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Linux/macOS (for Zeek network capture)
- 4GB RAM minimum

### 1. Start the Stack

```bash
docker-compose up --build
```

### 2. Access the Dashboard

Open your browser: **http://localhost:5001**

### 3. Generate Traffic (for Zeek to discover)

**Option A — Dashboard (Recommended)**  
Open the dashboard at **http://localhost:5001** and use the **Traffic Generator** panel to start any scenario with a single click. Live output streams directly in the UI.

**Option B — CLI Script (Linux only)**

```bash
# Run all traffic scenarios once (default)
./generate-traffic.sh

# Or run specific scenarios
./generate-traffic.sh web    # HTTPS web app only
./generate-traffic.sh ssh    # SSH service only
./generate-traffic.sh db     # PostgreSQL database only
./generate-traffic.sh mixed  # Simultaneous cross-service traffic
./generate-traffic.sh loop   # Continuously loop all scenarios
```

Alternatively, test services manually:

```bash
# Test HTTPS Web App
curl -k https://localhost:8443/api/data

# Test SSH Service (password: cbom_demo_2024!)
# Note: sshpass first
sshpass -p 'cbom_demo_2024!' ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null cbomuser@localhost

# Test Database (password: cbom_demo_pass)
# Note: install libpq 
# Then add to PATH
psql "postgresql://postgres:cbom_demo_pass@localhost:5432/crypto_inventory?sslmode=require"
```

### 4. View CBOM

The dashboard auto-refreshes every 60 seconds when new logs are detected. Click **Refresh** to force update via the API.

## Project Structure

```
cbom-discovery/
├── docker-compose.yml          # Orchestrates all services
├── generate-traffic.sh         # Traffic generator for sample apps
├── README.md                   # This file
│
├── zeek/                       # Network Monitor
│   ├── Dockerfile
│   ├── local.zeek             # Zeek site policy (JSON logs, SSL/SSH scripts)
│   └── scripts/
│       └── crypto-detection.zeek   # Loads base SSL/SSH/hash protocols
│
├── analyzer/                   # CBOM Analyzer & Dashboard
│   ├── Dockerfile
│   ├── requirements.txt        # Flask, watchdog, python-dateutil
│   ├── app.py                 # Flask web server + file watcher
│   ├── cbom_generator.py      # CBOM generation logic
│   └── templates/
│       └── index.html         # Dashboard UI
│
├── sample-apps/               # Target Applications
│   ├── web-app/               # HTTPS Flask app
│   │   ├── Dockerfile         # Generates self-signed RSA 2048 cert on build
│   │   ├── requirements.txt
│   │   └── app.py
│   ├── ssh-service/           # OpenSSH server
│   │   ├── Dockerfile         # Creates RSA, ECDSA, ED25519 host keys
│   │   └── sshd_config
│   └── database-service/      # PostgreSQL 16 with SSL
│       ├── Dockerfile         # Generates server + CA certificates
│       ├── postgresql.conf    # SSL/TLS 1.2-1.3 settings
│       ├── pg_hba.conf        # SCRAM-SHA-256 auth, SSL required
│       └── init.sql           # Sample crypto_inventory tables
│
└── shared/                    # Shared volumes
    ├── logs/                  # Zeek JSON log output
    └── cbom/                  # Generated CBOM JSON (cbom.json)
```

## Sample Applications Detail

### 1. Web Application (`sample-apps/web-app`)
- **Technology**: Flask + PyOpenSSL
- **Crypto**: TLS 1.2+, RSA 2048-bit self-signed certificate, AES-256-GCM, ECDHE
- **Port**: 8443
- **Purpose**: Demonstrates HTTPS/TLS discovery

### 2. SSH Service (`sample-apps/ssh-service`)
- **Technology**: OpenSSH server (Ubuntu 22.04)
- **Crypto**: RSA 2048, ECDSA P-521, Ed25519 host keys; AES-256-CTR/GCM, Curve25519/ECDH key exchange
- **Port**: 2222 (mapped to container port 22)
- **Purpose**: Demonstrates SSH crypto discovery
- **Credentials**: `cbomuser` / `cbom_demo_2024!`

### 3. Database Service (`sample-apps/database-service`)
- **Technology**: PostgreSQL 16 with SSL
- **Crypto**: TLS 1.2/1.3, SCRAM-SHA-256 auth, RSA 2048 certificates, AES-GCM
- **Port**: 5432 (PostgreSQL), 6432 (reserved)
- **Purpose**: Demonstrates database TLS discovery
- **Credentials**: `postgres` / `cbom_demo_pass`

## Zeek Crypto Detection

The Zeek configuration (`local.zeek`) enables:

| Feature | Description |
|---------|-------------|
| SSL/TLS | Standard Zeek SSL analyzer (heartbleed, known-certs) |
| SSH | Standard Zeek SSH analyzer (geo-data, bruteforce detection) |
| X.509 | Certificate logging via SSL analyzer |
| File Hashes | SHA-1, SHA-256, MD5 via `hash-all-files` framework |
| Output Format | JSON logs with ISO 8601 timestamps |

Zeek runs in **host network mode** (`network_mode: host`) with `NET_RAW` and `NET_ADMIN` capabilities to capture traffic on the host interface.

## CBOM Output Format

Generated CBOM follows this structure:

```json
{
  "metadata": {
    "tool": "CBOM Discovery Tool",
    "version": "1.0.0",
    "generated_at": "...",
    "format": "CBOM-1.0"
  },
  "summary": {
    "total_crypto_assets": 0,
    "total_services": 0,
    "total_findings": 0,
    "total_certificates": 0,
    "total_keys": 0,
    "risk_score": 0,
    "protocols": {},
    "algorithms": {},
    "key_lengths": {}
  },
  "crypto_assets": [
    {
      "id": "crypto-0",
      "type": "cipher",
      "algorithm": "...",
      "protocol": "tcp",
      "service": "ssl",
      "source": "...",
      "confidence": "medium",
      "timestamp": "...",
      "connection_uid": "...",
      "key_length": null,
      "hash_algorithm": null
    }
  ],
  "certificates": [
    {
      "id": "cert-0",
      "subject": "...",
      "issuer": "...",
      "serial": "...",
      "key_algorithm": "...",
      "signature_algorithm": "...",
      "key_length": 2048,
      "valid_from": "...",
      "valid_until": "...",
      "sha1_fingerprint": "...",
      "sha256_fingerprint": "...",
      "source": "x509"
    }
  ],
  "keys": [
    {
      "id": "ssh-0",
      "host_key": "...",
      "client_key": "...",
      "algorithm": "...",
      "source": "ssh",
      "timestamp": "..."
    }
  ],
  "services": [
    {
      "name": "ssl",
      "protocols": ["tcp"],
      "algorithms": ["..."],
      "asset_count": 1
    }
  ],
  "findings": [
    {
      "id": "finding-0",
      "severity": "high",
      "type": "algorithm_risk",
      "description": "...",
      "algorithm": "...",
      "crypto_type": "...",
      "recommendation": "..."
    }
  ]
}
```

## Analyzer Features

### Integrated Traffic Generator
The dashboard includes built-in controls to generate traffic against the sample applications without leaving your browser. Click any scenario button (Web, SSH, Database, Mixed, All, or Loop) and watch live output stream in the panel. A **Clear CBOM** button is also available to reset all discovered cryptographic assets, certificates, and findings.

### Auto-Regeneration
The analyzer uses `watchdog` to monitor the shared logs directory. CBOM is automatically regenerated when:
- New `.log` files are created
- Existing `.log` files are modified
- Every 60 seconds (periodic refresh)

### Risk Scoring

| Severity | Criteria | Score Impact |
|----------|----------|-------------|
| Critical | MD5, SHA1, RC4, DES, 3DES, DSA, <128-bit keys | +25 |
| High | RSA/DH <2048 bits, expired certificates | +15 |
| Medium | Legacy algorithms (RSA/DH ≥2048), certs expiring <30d, 128-255 bit keys | +5 |
| Low | Modern algorithms, adequate key lengths | 0 |

### Risk Recommendations

| Algorithm | Recommendation |
|-----------|---------------|
| MD5 | Replace with SHA-256 or SHA-3 |
| SHA-1 | Replace with SHA-256 or SHA-3 |
| RC4 | Disable RC4, use AES-GCM or ChaCha20-Poly1305 |
| DES/3DES | Replace with AES-256-GCM |
| RSA | Consider migrating to ECDSA or Ed25519 |
| DH | Use ECDHE with Curve25519 for key exchange |

## Traffic Generator

The `generate-traffic.sh` script automates network traffic generation across all sample applications to help Zeek discover cryptographic assets.

### Prerequisites
- `curl` (required)
- `sshpass` (optional, for SSH scenarios)
- `psql` (optional, for database scenarios)

### Usage

| Command | Description |
|---------|-------------|
| `./generate-traffic.sh` or `./generate-traffic.sh all` | Run all scenarios once |
| `./generate-traffic.sh web` | HTTPS web application traffic only |
| `./generate-traffic.sh ssh` | SSH service traffic only |
| `./generate-traffic.sh db` | PostgreSQL database traffic only |
| `./generate-traffic.sh mixed` | Simultaneous cross-service traffic |
| `./generate-traffic.sh loop` | Continuously loop all scenarios |
| `./generate-traffic.sh help` | Show help message |

### Scenarios

**Web Scenario**
- Fetches homepage, `/api/data`, and `/api/health`
- Simulates 10 rapid load requests

**SSH Scenario**
- Executes `uname -a`, `ls -la`, and `cat /etc/os-release`
- Opens 5 rapid SSH connections

**Database Scenario**
- Runs SELECT, COUNT, and INSERT queries on `crypto_inventory`
- Simulates 5 rapid DB connections over TLS

**Mixed Scenario**
- Runs web, SSH, and database requests in parallel

### Loop Mode

```bash
./generate-traffic.sh loop
```

Runs all scenarios continuously with a 10-second delay between iterations. Press `Ctrl+C` to stop.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main HTML dashboard |
| `/api/cbom` | GET | Full CBOM JSON |
| `/api/summary` | GET | Summary statistics only |
| `/api/findings` | GET | Security findings list |
| `/api/assets` | GET | Crypto assets list |
| `/api/certificates` | GET | X.509 certificates |
| `/api/services` | GET | Discovered services |
| `/api/refresh` | POST | Force CBOM regeneration |
| `/download/cbom` | GET | Download CBOM JSON file |
| `/api/traffic/<scenario>` | POST | Run traffic scenario (`web`, `ssh`, `db`, `mixed`, `all`, `loop`) |
| `/api/traffic/status` | GET | Traffic generator status and live output |
| `/api/traffic/stop` | POST | Stop active traffic generation |
| `/api/cbom/clear` | POST | Clear CBOM data (reset to empty) |

## Troubleshooting

### Zeek not capturing traffic
```bash
# Check interface name
docker exec zeek-monitor ip link show

# Run Zeek manually with correct interface
docker exec zeek-monitor zeek -i eth0 local
```

### No logs appearing
- Ensure sample apps are generating traffic
- Check shared volume permissions: `chmod 777 shared/logs`
- Verify Zeek is running: `docker logs zeek-monitor`

### Dashboard shows empty
- Wait 30-60 seconds for Zeek to process traffic
- Click **Refresh** button on dashboard
- Check analyzer logs: `docker logs cbom-analyzer`

## Security Notes

⚠️ **This is a demo tool**. Do not use in production without:
- Proper certificate management (not self-signed)
- Strong authentication
- Network segmentation
- Log retention policies
- Regular algorithm updates

## 1. System Context Diagram (C4 Level 1)

```mermaid
architecture-beta
    service analyst("Security Analyst")
    service cbom_system("CBOM Discovery System")[server]
    service target_infra("Target Infrastructure")[cloud]
    service export_dest("Export Destination")[disk]

    analyst --> cbom_system : Reviews crypto inventory
    cbom_system --> target_infra : Monitors network traffic
    cbom_system --> export_dest : Exports CBOM JSON
```

**Diagram Description**
This C4 Level 1 diagram shows the CBOM Discovery System at the center, used by a Security Analyst to review cryptographic inventory. The system monitors network traffic from Target Infrastructure and exports CBOM reports to a destination such as a SIEM or file store.

---

## 2. Container Diagram (C4 Level 2)

```mermaid
architecture-beta
    group cbom_platform("CBOM Discovery Platform")
    group target_env("Target Environment")

    service zeek("Zeek Monitor")[server] in cbom_platform
    service analyzer("Python Analyzer")[server] in cbom_platform
    service dashboard("HTML Dashboard")[server] in cbom_platform
    service logs_store("Log Storage")[disk] in cbom_platform
    service cbom_store("CBOM Storage")[disk] in cbom_platform

    service web_app("Web Application")[server] in target_env
    service ssh_svc("SSH Service")[server] in target_env
    service db_svc("Database Service")[database] in target_env

    zeek:R --> L:logs_store : Writes Zeek logs
    analyzer:R --> L:logs_store : Reads logs
    analyzer:R --> L:cbom_store : Writes CBOM JSON
    dashboard:R --> L:cbom_store : Reads CBOM
    dashboard:R --> L:analyzer : REST API

    zeek:R --> L:web_app : Monitors HTTPS
    zeek:R --> L:ssh_svc : Monitors SSH
    zeek:R --> L:db_svc : Monitors PostgreSQL
```

**Diagram Description**
This C4 Level 2 diagram decomposes the CBOM Discovery Platform into five containers: Zeek Monitor captures network traffic and writes logs; Python Analyzer parses logs and generates CBOM JSON; HTML Dashboard serves the UI via REST API; Log Storage and CBOM Storage are shared disk volumes. Three sample applications in the Target Environment provide cryptographic traffic for discovery.

---

## 3. Component Diagram (C4 Level 3) for the Python Analyzer

```mermaid
architecture-beta
    group analyzer_ctr("Python Analyzer Container")

    service flask_app("Flask Web Server")[server] in analyzer_ctr
    service api_router("API Router")[server] in analyzer_ctr
    service file_watcher("File Watcher")[server] in analyzer_ctr
    service log_parser("Log Parser")[server] in analyzer_ctr
    service cbom_gen("CBOM Generator")[server] in analyzer_ctr
    service risk_assessor("Risk Assessor")[server] in analyzer_ctr

    flask_app:R --> L:api_router : Route HTTP requests
    api_router:R --> L:cbom_gen : Request CBOM data
    file_watcher:R --> L:log_parser : New log detected
    log_parser:R --> L:cbom_gen : Parsed crypto events
    cbom_gen:R --> L:risk_assessor : Assets for scoring
    risk_assessor:L --> R:cbom_gen : Risk findings
```

**Diagram Description**
This C4 Level 3 diagram shows the internal components of the Python Analyzer container. The Flask Web Server routes requests through the API Router. The File Watcher detects new Zeek logs and triggers the Log Parser, which feeds parsed events to the CBOM Generator. The Risk Assessor evaluates cryptographic assets and returns findings back into the CBOM.

---

## 4. Deployment Diagram

```mermaid
architecture-beta
    group docker_host("Docker Host")

    service zeek("Zeek Container")[server] in docker_host
    service analyzer("Analyzer Container")[server] in docker_host
    service web_app("Web App Container")[server] in docker_host
    service ssh_svc("SSH Container")[server] in docker_host
    service db_svc("DB Container")[database] in docker_host

    service logs_vol("Logs Volume")[disk] in docker_host
    service cbom_vol("CBOM Volume")[disk] in docker_host

    zeek:R --> L:logs_vol : Mount read-write
    analyzer:R --> L:logs_vol : Mount read-only
    analyzer:R --> L:cbom_vol : Mount read-write

    zeek:R --> L:web_app : Traffic capture
    zeek:R --> L:ssh_svc : Traffic capture
    zeek:R --> L:db_svc : Traffic capture
```

**Diagram Description**
This deployment diagram shows all services running as Docker containers on a single host. Zeek has read-write access to the Logs Volume, while the Analyzer mounts it read-only and writes generated CBOM files to the CBOM Volume. Zeek captures traffic from the three sample application containers.

---

## 5. Runtime / Sequence Diagram 1 — Crypto Discovery Flow

```mermaid
sequenceDiagram
    actor Analyst
    participant WebApp as Web Application
    participant Zeek as Zeek Monitor
    participant Logs as Log Storage
    participant Analyzer as Python Analyzer
    participant Dashboard as HTML Dashboard

    Analyst->>WebApp: curl https://localhost:8443
    WebApp-->>Analyst: TLS handshake (RSA/AES/ECDHE)

    Zeek->>Zeek: Capture TLS traffic
    Zeek->>Logs: Write crypto.log, ssl.log, x509.log

    Analyzer->>Logs: Watch for new logs
    Logs-->>Analyzer: Return log entries

    Analyzer->>Analyzer: Parse crypto events
    Analyzer->>Analyzer: Generate CBOM JSON
    Analyzer->>Analyzer: Calculate risk score

    Analyst->>Dashboard: Open http://localhost:5000
    Dashboard->>Analyzer: GET /api/cbom
    Analyzer-->>Dashboard: Return CBOM data
    Dashboard-->>Analyst: Render findings and assets

    classDef user fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#000;
    classDef container fill:#f3e5f5,stroke:#4a148c,stroke-width:2px,color:#000;
    classDef database fill:#fff8e1,stroke:#f57f17,stroke-width:2px,color:#000;

    class Analyst user;
    class WebApp,Zeek,Analyzer,Dashboard container;
    class Logs database;
```

**Diagram Description**
This sequence diagram illustrates the end-to-end crypto discovery flow. The Analyst generates TLS traffic by curling the Web Application. Zeek captures the traffic and writes structured logs. The Python Analyzer detects new logs, parses cryptographic events, generates a CBOM, and scores risks. The Analyst then views the results through the HTML Dashboard.

---

## 6. Runtime / Sequence Diagram 2 — User Refresh Flow

```mermaid
sequenceDiagram
    actor Analyst
    participant Dashboard as HTML Dashboard
    participant API as API Router
    participant CBOMGen as CBOM Generator
    participant LogParser as Log Parser
    participant Logs as Log Storage

    Analyst->>Dashboard: Click Refresh button
    Dashboard->>API: POST /api/refresh

    API->>CBOMGen: Trigger regeneration
    CBOMGen->>LogParser: Process all logs

    LogParser->>Logs: Read crypto.log
    Logs-->>LogParser: SSL cipher entries
    LogParser->>Logs: Read certificates.log
    Logs-->>LogParser: X.509 entries
    LogParser->>Logs: Read ssh.log
    Logs-->>LogParser: SSH key entries

    LogParser-->>CBOMGen: Parsed crypto assets
    CBOMGen->>CBOMGen: Assess risks
    CBOMGen->>CBOMGen: Build summary

    CBOMGen-->>API: Updated CBOM object
    API-->>Dashboard: JSON response
    Dashboard-->>Analyst: Update UI with new data

    classDef user fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#000;
    classDef container fill:#f3e5f5,stroke:#4a148c,stroke-width:2px,color:#000;
    classDef database fill:#fff8e1,stroke:#f57f17,stroke-width:2px,color:#000;

    class Analyst user;
    class Dashboard,API,CBOMGen,LogParser container;
    class Logs database;
```

**Diagram Description**
This sequence diagram shows the synchronous refresh flow initiated by the Analyst. The Dashboard forwards the refresh request to the API Router, which triggers the CBOM Generator. The Log Parser reads all Zeek log types (crypto, certificates, SSH) and returns parsed assets. The CBOM Generator reassesses risks, rebuilds the summary, and returns the updated CBOM to the Dashboard for rendering.

---

## 7. Data Model / ER Diagram

```mermaid
erDiagram
    CBOM ||--o{ CRYPTO_ASSET : contains
    CBOM ||--o{ CERTIFICATE : contains
    CBOM ||--o{ CRYPTO_KEY : contains
    CBOM ||--o{ SERVICE : contains
    CBOM ||--o{ FINDING : contains
    CBOM ||--|| SUMMARY : has

    CBOM {
        string tool
        string version
        timestamp generated_at
        string format
    }

    SUMMARY {
        int total_crypto_assets
        int total_services
        int risk_score
        int total_findings
        int total_certificates
        int total_keys
    }

    CRYPTO_ASSET {
        string id
        string type
        string algorithm
        string protocol
        string service
        string source
        string confidence
        timestamp timestamp
        string connection_uid
        int key_length
        string hash_algorithm
    }

    CERTIFICATE {
        string id
        string subject
        string issuer
        string serial
        string key_algorithm
        string signature_algorithm
        int key_length
        timestamp valid_from
        timestamp valid_until
        string sha1_fingerprint
        string sha256_fingerprint
        string source
    }

    CRYPTO_KEY {
        string id
        string host_key
        string client_key
        string key_alg
        string source
        timestamp ts
    }

    SERVICE {
        string name
        string protocols
        string algorithms
        int asset_count
    }

    FINDING {
        string id
        string severity
        string type
        string description
        string algorithm
        string crypto_type
        string recommendation
    }
```

**Diagram Description**
This ER diagram models the CBOM JSON structure produced by the Python Analyzer. A single CBOM record contains metadata, one summary aggregate, and collections of crypto assets, certificates, keys, discovered services, and security findings. Each entity captures fields necessary for inventory and risk assessment.

---

## 8. Network / Infrastructure Diagram

```mermaid
architecture-beta
    group docker_host("Docker Host")

    service host("Host OS")[server] in docker_host
    service bridge("Docker Bridge")[cloud] in docker_host

    service zeek("Zeek\neth0/any")[server] in docker_host
    service analyzer("Analyzer\n:5000")[server] in docker_host
    service web_app("Web App\n:8443")[server] in docker_host
    service ssh_svc("SSH\n:2222")[server] in docker_host
    service db_svc("Database\n:5432")[database] in docker_host

    service logs_vol("Logs Volume")[disk] in docker_host
    service cbom_vol("CBOM Volume")[disk] in docker_host

    host --> bridge : Network bridge
    bridge --> zeek
    bridge --> analyzer
    bridge --> web_app
    bridge --> ssh_svc
    bridge --> db_svc

    zeek:R --> L:logs_vol : Shared mount
    analyzer:R --> L:logs_vol : Shared mount
    analyzer:R --> L:cbom_vol : Shared mount

    zeek:R --> L:web_app : Traffic capture
    zeek:R --> L:ssh_svc : Traffic capture
    zeek:R --> L:db_svc : Traffic capture
```

**Diagram Description**
This network diagram shows the Docker infrastructure topology. All containers connect through the Docker Bridge. Zeek monitors traffic to the Web App (8443), SSH Service (2222), and Database (5432). The Analyzer exposes port 5000 for the dashboard. Logs Volume and CBOM Volume are shared mounts between Zeek and the Analyzer.