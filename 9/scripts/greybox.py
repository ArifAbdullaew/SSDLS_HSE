#!/usr/bin/env python3
"""
Grey-box DAST scan using OWASP ZAP.

ZAP is configured with:
  - form-based authentication to /login (PostgreSQL credentials)
  - cookie-based session management
  - logged-in/logged-out page indicators
  - forced-user mode so every request is authenticated

Steps: create context  configure auth  authenticated spider  active scan
        save raw alerts  generate HTML/JSON reports.
"""
import json
import sys
import time
import urllib.parse
from datetime import datetime

sys.path.insert(0, '/scripts')
from zap_client import ZAPClient

ZAP_HOST      = 'zap'
ZAP_PORT      = 8080
TARGET        = 'http://web:5000'
REPORT_DIR    = '/zap/wrk'
CONTEXT_NAME  = 'GreyBox'

# PostgreSQL credentials that the Flask login form sends
DB_HOST = 'db'
DB_PORT = '5432'
DB_NAME = 'cve_db'
DB_USER = 'postgres'
DB_PASS = 'postgres'

RISK_ORDER = {'High': 0, 'Medium': 1, 'Low': 2, 'Informational': 3}


def main() -> None:
    zap = ZAPClient(ZAP_HOST, ZAP_PORT)

    if not zap.wait_ready():
        sys.exit(1)

    # Fresh session — clears black-box state
    print('\nStarting new ZAP session (greybox)...', flush=True)
    zap.new_session('greybox')

    # ── Create context ────────────────────────────────────────────────────────
    print(f'\nCreating context: {CONTEXT_NAME}', flush=True)
    ctx_id = zap.new_context(CONTEXT_NAME)
    print(f'  Context ID: {ctx_id}', flush=True)

    zap.include_in_context(CONTEXT_NAME, f'{TARGET}.*')
    # Exclude /logout to avoid ZAP logging itself out during the scan
    zap.exclude_from_context(CONTEXT_NAME, rf'{TARGET}/logout.*')

    # ── Session management: cookies ───────────────────────────────────────────
    zap.set_session_mgmt(ctx_id, 'cookieBasedSessionManagement')
    print('  Session management: cookieBasedSessionManagement', flush=True)

    # ── Form-based authentication ─────────────────────────────────────────────
    # The Flask login form accepts: host, port, dbname, user, password
    # ZAP substitutes {%username%} → DB_USER and {%password%} → DB_PASS
    login_url  = f'{TARGET}/login'
    login_data = (
        f'host={DB_HOST}&port={DB_PORT}&dbname={DB_NAME}'
        '&user={%username%}&password={%password%}'
    )
    auth_config = urllib.parse.urlencode({
        'loginUrl': login_url,
        'loginRequestData': login_data,
    })
    zap.set_auth_method(ctx_id, 'formBasedAuthentication', auth_config)
    print(f'  Auth method  : formBasedAuthentication', flush=True)
    print(f'  Login URL    : {login_url}', flush=True)
    print(f'  Login fields : host, port, dbname, user={{%username%}}, password={{%password%}}', flush=True)

    # Logged-in  → nav bar contains logout link
    # Logged-out → page contains the login form action
    zap.set_logged_in_indicator(ctx_id,  r'href="/logout"')
    zap.set_logged_out_indicator(ctx_id, r'action="/login"')
    print('  Indicators configured.', flush=True)

    # ── User ──────────────────────────────────────────────────────────────────
    user_id = zap.new_user(ctx_id, 'pg-admin')
    creds   = urllib.parse.urlencode({'username': DB_USER, 'password': DB_PASS})
    zap.set_user_creds(ctx_id, user_id, creds)
    zap.set_user_enabled(ctx_id, user_id, True)
    print(f'  User created : {DB_USER} (ID={user_id})', flush=True)

    # Forced-user mode: ZAP re-authenticates when session expires
    zap.set_forced_user(ctx_id, user_id)
    zap.forced_user_mode(True)
    print('  Forced-user mode: ON', flush=True)

    # ── Wait for web app ──────────────────────────────────────────────────────
    print(f'\nChecking target: {TARGET}', flush=True)
    for attempt in range(15):
        try:
            zap.access_url(TARGET)
            print('  Target is reachable.', flush=True)
            break
        except Exception:
            print(f'  Waiting for web app... ({attempt + 1}/15)', flush=True)
            time.sleep(10)
    else:
        print('ERROR: web app is not reachable. Exiting.', flush=True)
        sys.exit(1)

    # Small pause so the initial auth request settles
    time.sleep(3)

    # ── Authenticated spider ──────────────────────────────────────────────────
    print('\n=== SPIDER (authenticated) ===', flush=True)
    spider_id = zap.spider_scan(TARGET, context_name=CONTEXT_NAME, user_id=user_id)
    print(f'Spider scan ID: {spider_id}', flush=True)
    zap.wait_spider(spider_id)

    urls = zap.spider_results(spider_id)
    print(f'URLs discovered: {len(urls)}', flush=True)
    for u in urls:
        print(f'  {u}', flush=True)

    # ── Authenticated active scan ─────────────────────────────────────────────
    print('\n=== ACTIVE SCAN (authenticated) ===', flush=True)
    ascan_id = zap.ascan_scan(TARGET, context_id=ctx_id, user_id=user_id)
    print(f'Active scan ID: {ascan_id}', flush=True)
    zap.wait_ascan(ascan_id)

    # Turn off forced-user before report generation
    zap.forced_user_mode(False)

    # ── Collect & display alerts ──────────────────────────────────────────────
    alerts = zap.alerts(TARGET)
    print(f'\n=== ALERTS: {len(alerts)} total ===', flush=True)
    sorted_alerts = sorted(alerts, key=lambda a: RISK_ORDER.get(a['risk'], 9))
    for a in sorted_alerts:
        risk = a.get('risk', '?')
        name = a.get('name', a.get('alert', '?'))
        url  = a.get('url', '?')
        conf = a.get('confidence', '?')
        print(f'  [{risk:13s}|{conf:6s}] {name[:55]:<55} {url}', flush=True)

    # ── Save raw JSON ─────────────────────────────────────────────────────────
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    raw_path = f'{REPORT_DIR}/greybox_alerts_{ts}.json'
    with open(raw_path, 'w', encoding='utf-8') as fh:
        json.dump(alerts, fh, indent=2, ensure_ascii=False)
    print(f'\nRaw alerts JSON: {raw_path}', flush=True)

    # ── HTML report ───────────────────────────────────────────────────────────
    print('\n=== GENERATING REPORTS ===', flush=True)
    try:
        zap.generate_report(
            title=f'Grey-Box Scan — {datetime.now().strftime("%Y-%m-%d %H:%M")}',
            template='traditional-html',
            filename=f'greybox_report_{ts}.html',
            report_dir=REPORT_DIR,
        )
        print(f'HTML  → {REPORT_DIR}/greybox_report_{ts}.html', flush=True)
    except Exception as exc:
        print(f'HTML report failed: {exc}', flush=True)

    try:
        zap.generate_report(
            title=f'Grey-Box Scan — {datetime.now().strftime("%Y-%m-%d %H:%M")}',
            template='traditional-json',
            filename=f'greybox_report_{ts}.json',
            report_dir=REPORT_DIR,
        )
        print(f'JSON  → {REPORT_DIR}/greybox_report_{ts}.json', flush=True)
    except Exception as exc:
        print(f'JSON report failed: {exc}', flush=True)

    print('\n[+] Grey-box scan complete.', flush=True)


if __name__ == '__main__':
    main()
