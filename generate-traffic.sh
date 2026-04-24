#!/bin/bash
# =============================================================================
# CBOM Discovery Tool - Traffic Generator
# =============================================================================
# Generates network traffic for all sample applications to enable Zeek
# network monitoring and CBOM generation.
#
# Scenarios:
#   1. HTTPS Web Application  (port 8443)
#   2. SSH Service            (port 2222)
#   3. PostgreSQL Database    (port 5432, TLS enabled)
#
# Usage:
#   ./generate-traffic.sh [all|web|ssh|db|loop]
#
# Examples:
#   ./generate-traffic.sh all      # Run all scenarios once
#   ./generate-traffic.sh web      # Run web app scenarios only
#   ./generate-traffic.sh loop     # Loop all scenarios continuously
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TRAFFIC_HOST="${TRAFFIC_HOST:-localhost}"
WEB_APP_URL="https://${TRAFFIC_HOST}:8443"
SSH_HOST="${TRAFFIC_HOST}"
SSH_PORT="2222"
SSH_USER="cbomuser"
SSH_PASS="cbom_demo_2024!"
DB_HOST="${TRAFFIC_HOST}"
DB_PORT="5432"
DB_USER="postgres"
DB_PASS="cbom_demo_pass"
DB_NAME="crypto_inventory"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log_info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_err()   { echo -e "${RED}[ERROR]${NC} $*"; }

separator() { echo -e "${BLUE}----------------------------------------${NC}"; }

# ---------------------------------------------------------------------------
# Dependency Checks
# ---------------------------------------------------------------------------
check_deps() {
    log_info "Checking dependencies..."

    if ! command -v curl &>/dev/null; then
        log_err "curl is required but not installed."
        exit 1
    fi

    if ! command -v sshpass &>/dev/null; then
        log_warn "sshpass not found. SSH scenarios will be skipped."
        log_warn "Install on macOS: brew install sshpass"
        log_warn "Install on Ubuntu/Debian: sudo apt-get install sshpass"
        SSH_AVAILABLE=false
    else
        SSH_AVAILABLE=true
    fi

    if ! command -v psql &>/dev/null; then
        log_warn "psql (PostgreSQL client) not found. Database scenarios will be skipped."
        log_warn "Install on macOS: brew install libpq  &&  export PATH=\"/opt/homebrew/opt/libpq/bin:\$PATH\""
        log_warn "Install on Ubuntu/Debian: sudo apt-get install postgresql-client"
        DB_AVAILABLE=false
    else
        DB_AVAILABLE=true
    fi

    log_ok "Dependency check complete."
    echo
}

# ---------------------------------------------------------------------------
# Scenario 1: HTTPS Web Application Traffic
# ---------------------------------------------------------------------------
scenario_web() {
    separator
    log_info "SCENARIO: HTTPS Web Application (port 8443)"
    separator

    # 1.1 Homepage (HTML over TLS)
    log_info "1.1 Fetching homepage..."
    curl -sk -o /dev/null -w "Status: %{http_code}, Time: %{time_total}s\n" \
         "${WEB_APP_URL}/" || log_err "Homepage request failed"

    # 1.2 API data endpoint (JSON over TLS)
    log_info "1.2 Fetching /api/data ..."
    curl -sk -o /dev/null -w "Status: %{http_code}, Time: %{time_total}s\n" \
         "${WEB_APP_URL}/api/data" || log_err "API data request failed"

    # 1.3 Health check
    log_info "1.3 Fetching /api/health ..."
    curl -sk -o /dev/null -w "Status: %{http_code}, Time: %{time_total}s\n" \
         "${WEB_APP_URL}/api/health" || log_err "Health check failed"

    # 1.4 Multiple rapid requests (simulate load)
    log_info "1.4 Simulating load with 10 rapid requests..."
    for i in $(seq 1 10); do
        curl -sk -o /dev/null "${WEB_APP_URL}/api/data" &
    done
    wait
    log_ok "Web scenario complete."
    echo
}

# ---------------------------------------------------------------------------
# Scenario 2: SSH Service Traffic
# ---------------------------------------------------------------------------
scenario_ssh() {
    if [ "$SSH_AVAILABLE" != "true" ]; then
        log_warn "Skipping SSH scenario (sshpass unavailable)."
        echo
        return
    fi

    separator
    log_info "SCENARIO: SSH Service (port 2222)"
    separator

    # 2.1 SSH connection + execute command (triggers key exchange)
    log_info "2.1 SSH login and execute 'uname -a'..."
    sshpass -p "$SSH_PASS" ssh -p "$SSH_PORT" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        "${SSH_USER}@${SSH_HOST}" \
        "uname -a" || log_err "SSH command execution failed"

    # 2.2 SSH connection + list files
    log_info "2.2 SSH login and execute 'ls -la'..."
    sshpass -p "$SSH_PASS" ssh -p "$SSH_PORT" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        "${SSH_USER}@${SSH_HOST}" \
        "ls -la" || log_err "SSH command execution failed"

    # 2.3 SCP-like transfer simulation (cat remote file)
    log_info "2.3 SSH cat /etc/os-release ..."
    sshpass -p "$SSH_PASS" ssh -p "$SSH_PORT" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        "${SSH_USER}@${SSH_HOST}" \
        "cat /etc/os-release" >/dev/null || log_err "SSH cat failed"

    # 2.4 Multiple SSH connections (different key exchange opportunities)
    log_info "2.4 Opening 5 rapid SSH connections..."
    for i in $(seq 1 5); do
        sshpass -p "$SSH_PASS" ssh -p "$SSH_PORT" \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            -o ConnectTimeout=5 \
            "${SSH_USER}@${SSH_HOST}" \
            "echo 'connection $i ok'" >/dev/null &
    done
    wait
    log_ok "SSH scenario complete."
    echo
}

# ---------------------------------------------------------------------------
# Scenario 3: PostgreSQL Database Traffic (TLS)
# ---------------------------------------------------------------------------
scenario_db() {
    if [ "$DB_AVAILABLE" != "true" ]; then
        log_warn "Skipping Database scenario (psql unavailable)."
        echo
        return
    fi

    separator
    log_info "SCENARIO: PostgreSQL Database with TLS (port 5432)"
    separator

    local connstr="postgresql://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=require"

    # 3.1 Simple connection + query
    log_info "3.1 Executing SELECT query on crypto_inventory..."
    psql "$connstr" -c "SELECT * FROM crypto_inventory LIMIT 5;" >/dev/null 2>&1 || log_err "DB query failed"

    # 3.2 Query certificates table
    log_info "3.2 Executing SELECT query on certificates..."
    psql "$connstr" -c "SELECT * FROM certificates LIMIT 5;" >/dev/null 2>&1 || log_err "DB query failed"

    # 3.3 Count rows
    log_info "3.3 Counting rows in crypto_inventory..."
    psql "$connstr" -c "SELECT COUNT(*) FROM crypto_inventory;" >/dev/null 2>&1 || log_err "DB count failed"

    # 3.4 Insert a new record
    log_info "3.4 Inserting new crypto asset record..."
    psql "$connstr" -c "
        INSERT INTO crypto_inventory (asset_name, algorithm, key_length, protocol, risk_level)
        VALUES ('Traffic-Gen-Test', 'AES-256-GCM', 256, 'TLS 1.3', 'low');
    " >/dev/null 2>&1 || log_err "DB insert failed"

    # 3.5 Multiple rapid connections
    log_info "3.5 Simulating 5 rapid DB connections..."
    for i in $(seq 1 5); do
        psql "$connstr" -c "SELECT 1;" >/dev/null 2>&1 &
    done
    wait
    log_ok "Database scenario complete."
    echo
}

# ---------------------------------------------------------------------------
# Scenario 4: Mixed / Cross-Service Traffic
# ---------------------------------------------------------------------------
scenario_mixed() {
    separator
    log_info "SCENARIO: Mixed Cross-Service Traffic"
    separator

    log_info "4.1 Simulating parallel web + ssh + db requests..."

    # Web request in background
    curl -sk -o /dev/null "${WEB_APP_URL}/api/data" &

    # SSH in background (if available)
    if [ "$SSH_AVAILABLE" = "true" ]; then
        sshpass -p "$SSH_PASS" ssh -p "$SSH_PORT" \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            -o ConnectTimeout=5 \
            "${SSH_USER}@${SSH_HOST}" \
            "echo 'mixed ssh'" >/dev/null 2>&1 &
    fi

    # DB in background (if available)
    if [ "$DB_AVAILABLE" = "true" ]; then
        local connstr="postgresql://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=require"
        psql "$connstr" -c "SELECT 'mixed db';" >/dev/null 2>&1 &
    fi

    wait
    log_ok "Mixed scenario complete."
    echo
}

# ---------------------------------------------------------------------------
# Loop Mode
# ---------------------------------------------------------------------------
run_loop() {
    log_info "Starting continuous traffic generation loop."
    log_info "Press Ctrl+C to stop."
    echo

    local iteration=1
    while true; do
        separator
        log_info "=== ITERATION $iteration ==="
        separator
        echo

        scenario_web
        scenario_ssh
        scenario_db
        scenario_mixed

        log_info "Iteration $iteration complete. Sleeping 10 seconds..."
        echo
        sleep 10
        iteration=$((iteration + 1))
    done
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    echo
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║          CBOM Discovery Tool - Traffic Generator             ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo

    check_deps

    local mode="${1:-all}"

    case "$mode" in
        web)
            scenario_web
            ;;
        ssh)
            scenario_ssh
            ;;
        db)
            scenario_db
            ;;
        mixed)
            scenario_mixed
            ;;
        all)
            scenario_web
            scenario_ssh
            scenario_db
            scenario_mixed
            separator
            log_ok "All scenarios completed successfully!"
            separator
            echo
            log_info "Check the CBOM dashboard: http://localhost:5001"
            log_info "Zeek logs directory: ./shared/logs/"
            ;;
        loop)
            run_loop
            ;;
        help|--help|-h)
            cat <<EOF
Usage: $0 [all|web|ssh|db|mixed|loop|help]

  all    - Run all traffic scenarios once (default)
  web    - HTTPS web application traffic only
  ssh    - SSH service traffic only
  db     - PostgreSQL database traffic only
  mixed  - Simultaneous cross-service traffic
  loop   - Continuously loop all scenarios
  help   - Show this help message

Examples:
  $0              # Run all scenarios
  $0 web          # Test web app only
  $0 loop         # Generate traffic continuously
EOF
            ;;
        *)
            log_err "Unknown mode: $mode"
            echo "Run '$0 help' for usage information."
            exit 1
            ;;
    esac
}

main "$@"
