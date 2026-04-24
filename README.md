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

```bash
# Test HTTPS Web App
curl -k https://localhost:8443/api/data

# Test SSH Service (password: cbom_demo_2024!)
# Note: On macOS, install sshpass first: brew install sshpass
sshpass -p 'cbom_demo_2024!' ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null cbomuser@localhost

# Test Database (password: cbom_demo_pass)
# Note: On macOS, install libpq first: brew install libpq
# Then add to PATH: export PATH="/opt/homebrew/opt/libpq/bin:$PATH"
psql "postgresql://postgres:cbom_demo_pass@localhost:5432/crypto_inventory?sslmode=require"
```

### 4. View CBOM

The dashboard auto-refreshes every 60 seconds when new logs are detected. Click **Refresh** to force update via the API.

## Project Structure

```
cbom-discovery/
├── docker-compose.yml          # Orchestrates all services
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

## License

MIT License - For educational and testing purposes.
