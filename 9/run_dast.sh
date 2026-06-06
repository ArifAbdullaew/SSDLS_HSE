#!/usr/bin/env bash
# ============================================================
# run_dast.sh — DAST pipeline for CVE web application
#
# Workflow:
#   1. Start db + web + zap (docker compose up)
#   2. Wait for ZAP API to become available
#   3. Run black-box scan  (unauthenticated)
#   4. Run grey-box scan   (authenticated, form-based auth)
#   5. Print report locations
#
# All scanners run inside Docker on the task9_net network.
# Reports land in ./reports/  (mapped into the ZAP container).
#
# Prerequisites: Docker + Docker Compose v2
# Run from Git Bash / WSL / any POSIX shell on Windows.
# ============================================================
set -euo pipefail
cd "$(dirname "$0")"

NETWORK="task9_net"
ZAP_API="http://localhost:8090"
REPORTS_DIR="$(pwd)/reports"
SCANNER_IMAGE="python:3.12-slim"

log() { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }

# ── 1. Build images and start services ───────────────────────────────────────
log "Starting infrastructure: db + web + zap..."
docker compose up -d --build

# ── 2. Wait for ZAP daemon (up to 3 min) ─────────────────────────────────────
log "Waiting for ZAP API at ${ZAP_API}..."
for i in $(seq 1 36); do
  if curl -sf "${ZAP_API}/JSON/core/view/version/" > /dev/null 2>&1; then
    log "ZAP API ready (attempt ${i}/36)."
    break
  fi
  if [ "$i" -eq 36 ]; then
    log "ERROR: ZAP did not start within 3 minutes. Check: docker compose logs zap"
    exit 1
  fi
  sleep 5
done

# ── Helper: run a Python scan script inside Docker on task9_net ───────────────
run_scan() {
  local script="$1"
  docker run --rm \
    --network "${NETWORK}" \
    -v "${REPORTS_DIR}:/zap/wrk:rw" \
    -v "$(pwd)/scripts:/scripts:ro" \
    "${SCANNER_IMAGE}" \
    bash -c "pip install requests -q && python3 /scripts/${script}"
}

# ── 3. Black-box scan ─────────────────────────────────────────────────────────
log "==================================================================="
log " BLACK-BOX SCAN (no authentication)"
log "==================================================================="
run_scan "blackbox.py"

# ── 4. Grey-box scan ──────────────────────────────────────────────────────────
log "==================================================================="
log " GREY-BOX SCAN (form auth: postgres/postgres via /login)"
log "==================================================================="
run_scan "greybox.py"

# ── 5. Summary ────────────────────────────────────────────────────────────────
log "==================================================================="
log " All scans complete. Reports:"
ls -lh "${REPORTS_DIR}"
log "==================================================================="
