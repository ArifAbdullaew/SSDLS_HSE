# ============================================================
# run_dast.ps1 — DAST pipeline for CVE web application (PowerShell)
#
# Same workflow as run_dast.sh, for Windows PowerShell users.
# Prerequisites: Docker Desktop, Docker Compose v2
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Set-Location $PSScriptRoot

$NETWORK       = "task9_net"
$ZAP_API       = "http://localhost:8090"
$REPORTS_DIR   = Join-Path $PSScriptRoot "reports"
$SCANNER_IMAGE = "python:3.12-slim"

function Log($msg) {
    Write-Host "[$([datetime]::Now.ToString('HH:mm:ss'))] $msg"
}

# ── 1. Build and start services ───────────────────────────────────────────────
Log "Starting infrastructure: db + web + zap..."
docker compose up -d --build

# ── 2. Wait for ZAP API ───────────────────────────────────────────────────────
Log "Waiting for ZAP API at $ZAP_API..."
$ready = $false
for ($i = 1; $i -le 36; $i++) {
    try {
        $null = Invoke-WebRequest -Uri "$ZAP_API/JSON/core/view/version/" -UseBasicParsing -TimeoutSec 5
        Log "ZAP API ready (attempt $i/36)."
        $ready = $true
        break
    } catch {
        Start-Sleep -Seconds 5
    }
}
if (-not $ready) {
    Log "ERROR: ZAP did not start within 3 minutes."
    exit 1
}

# ── Helper: run a Python scan script in Docker ────────────────────────────────
function Invoke-Scan($Script) {
    $reportsMount = "${REPORTS_DIR}:/zap/wrk:rw".Replace('\', '/')
    $scriptsMount = "$(Join-Path $PSScriptRoot 'scripts'):/scripts:ro".Replace('\', '/')
    docker run --rm `
        --network $NETWORK `
        -v $reportsMount `
        -v $scriptsMount `
        $SCANNER_IMAGE `
        bash -c "pip install requests -q && python3 /scripts/$Script"
}

# ── 3. Black-box scan ─────────────────────────────────────────────────────────
Log "==================================================================="
Log " BLACK-BOX SCAN (no authentication)"
Log "==================================================================="
Invoke-Scan "blackbox.py"

# ── 4. Grey-box scan ──────────────────────────────────────────────────────────
Log "==================================================================="
Log " GREY-BOX SCAN (form auth: postgres/postgres via /login)"
Log "==================================================================="
Invoke-Scan "greybox.py"

# ── 5. Summary ────────────────────────────────────────────────────────────────
Log "==================================================================="
Log " All scans complete. Reports:"
Get-ChildItem $REPORTS_DIR | Format-Table Name, Length, LastWriteTime
Log "==================================================================="
