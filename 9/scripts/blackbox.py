#!/usr/bin/env python3
"""
Black-box DAST scan using OWASP ZAP.

No authentication is configured — ZAP behaves as an external attacker.
Steps: passive spider  active scan  save raw alerts  generate HTML/JSON reports.
"""
import json
import sys
import time
from datetime import datetime

sys.path.insert(0, '/scripts')
from zap_client import ZAPClient

ZAP_HOST   = 'zap'
ZAP_PORT   = 8080
TARGET     = 'http://web:5000'
REPORT_DIR = '/zap/wrk'

RISK_ORDER = {'High': 0, 'Medium': 1, 'Low': 2, 'Informational': 3}


def main() -> None:
    zap = ZAPClient(ZAP_HOST, ZAP_PORT)

    if not zap.wait_ready():
        sys.exit(1)

    # ── Wait for the web app ──────────────────────────────────────────────────
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

    # ── Spider ────────────────────────────────────────────────────────────────
    print('\n=== SPIDER (unauthenticated) ===', flush=True)
    spider_id = zap.spider_scan(TARGET)
    print(f'Spider scan ID: {spider_id}', flush=True)
    zap.wait_spider(spider_id)

    urls = zap.spider_results(spider_id)
    print(f'URLs discovered: {len(urls)}', flush=True)
    for u in urls:
        print(f'  {u}', flush=True)

    # ── Active scan ───────────────────────────────────────────────────────────
    print('\n=== ACTIVE SCAN (unauthenticated) ===', flush=True)
    ascan_id = zap.ascan_scan(TARGET)
    print(f'Active scan ID: {ascan_id}', flush=True)
    zap.wait_ascan(ascan_id)

    # ── Collect & display alerts ──────────────────────────────────────────────
    alerts = zap.alerts(TARGET)
    print(f'\n=== ALERTS: {len(alerts)} total ===', flush=True)
    sorted_alerts = sorted(alerts, key=lambda a: RISK_ORDER.get(a['risk'], 9))
    for a in sorted_alerts:
        risk  = a.get('risk', '?')
        name  = a.get('name', a.get('alert', '?'))
        url   = a.get('url', '?')
        conf  = a.get('confidence', '?')
        print(f'  [{risk:13s}|{conf:6s}] {name[:55]:<55} {url}', flush=True)

    # ── Save raw JSON ─────────────────────────────────────────────────────────
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    raw_path = f'{REPORT_DIR}/blackbox_alerts_{ts}.json'
    with open(raw_path, 'w', encoding='utf-8') as fh:
        json.dump(alerts, fh, indent=2, ensure_ascii=False)
    print(f'\nRaw alerts JSON: {raw_path}', flush=True)

    # ── HTML report ───────────────────────────────────────────────────────────
    print('\n=== GENERATING REPORTS ===', flush=True)
    try:
        zap.generate_report(
            title=f'Black-Box Scan — {datetime.now().strftime("%Y-%m-%d %H:%M")}',
            template='traditional-html',
            filename=f'blackbox_report_{ts}.html',
            report_dir=REPORT_DIR,
        )
        print(f'HTML  → {REPORT_DIR}/blackbox_report_{ts}.html', flush=True)
    except Exception as exc:
        print(f'HTML report failed: {exc}', flush=True)

    try:
        zap.generate_report(
            title=f'Black-Box Scan — {datetime.now().strftime("%Y-%m-%d %H:%M")}',
            template='traditional-json',
            filename=f'blackbox_report_{ts}.json',
            report_dir=REPORT_DIR,
        )
        print(f'JSON  → {REPORT_DIR}/blackbox_report_{ts}.json', flush=True)
    except Exception as exc:
        print(f'JSON report failed: {exc}', flush=True)

    print('\n[+] Black-box scan complete.', flush=True)


if __name__ == '__main__':
    main()
