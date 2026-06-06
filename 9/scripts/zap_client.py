"""Minimal ZAP REST API client (depends only on requests)."""
import time
import requests


class ZAPClient:
    def __init__(self, host: str = 'zap', port: int = 8080):
        self.base = f'http://{host}:{port}'
        self._s = requests.Session()

    # ── HTTP primitives ───────────────────────────────────────────────────────

    def _get(self, path: str, **params) -> dict:
        r = self._s.get(f'{self.base}{path}', params=params, timeout=60)
        r.raise_for_status()
        return r.json()

    def _post(self, path: str, **data) -> dict:
        r = self._s.post(f'{self.base}{path}', data=data, timeout=60)
        r.raise_for_status()
        return r.json()

    # ── Core ──────────────────────────────────────────────────────────────────

    def version(self) -> str:
        return self._get('/JSON/core/view/version/')['version']

    def new_session(self, name: str = '') -> None:
        self._post('/JSON/core/action/newSession/', name=name, overwrite='true')

    def access_url(self, url: str) -> dict:
        return self._get('/JSON/core/action/accessUrl/', url=url, followredirects='true')

    def alerts(self, baseurl: str = '', count: int = 5000) -> list:
        return self._get('/JSON/core/view/alerts/',
                         baseurl=baseurl, start=0, count=count)['alerts']

    # ── Spider ────────────────────────────────────────────────────────────────

    def spider_scan(self, url: str, context_name: str = '', user_id: str = '') -> str:
        p: dict = {'url': url, 'recurse': 'true', 'maxChildren': '0'}
        if context_name:
            p['contextName'] = context_name
        if user_id:
            p['userId'] = user_id
        return self._get('/JSON/spider/action/scan/', **p)['scan']

    def spider_status(self, scan_id: str) -> int:
        return int(self._get('/JSON/spider/view/status/', scanId=scan_id)['status'])

    def spider_results(self, scan_id: str) -> list:
        return self._get('/JSON/spider/view/results/', scanId=scan_id)['results']

    def wait_spider(self, scan_id: str, interval: int = 5) -> None:
        while True:
            s = self.spider_status(scan_id)
            print(f'  Spider: {s}%', flush=True)
            if s >= 100:
                break
            time.sleep(interval)

    # ── Active scan ───────────────────────────────────────────────────────────

    def ascan_scan(self, url: str, context_id: str = '', user_id: str = '') -> str:
        p: dict = {'url': url, 'recurse': 'true', 'inScopeOnly': 'false'}
        if context_id:
            p['contextId'] = context_id
        if user_id:
            p['userId'] = user_id
        return self._get('/JSON/ascan/action/scan/', **p)['scan']

    def ascan_status(self, scan_id: str) -> int:
        return int(self._get('/JSON/ascan/view/status/', scanId=scan_id)['status'])

    def wait_ascan(self, scan_id: str, interval: int = 20) -> None:
        while True:
            s = self.ascan_status(scan_id)
            print(f'  Active scan: {s}%', flush=True)
            if s >= 100:
                break
            time.sleep(interval)

    # ── Context ───────────────────────────────────────────────────────────────

    def new_context(self, name: str) -> str:
        return self._post('/JSON/context/action/newContext/',
                          contextName=name)['contextId']

    def include_in_context(self, name: str, regex: str) -> None:
        self._post('/JSON/context/action/includeInContext/',
                   contextName=name, regex=regex)

    def exclude_from_context(self, name: str, regex: str) -> None:
        self._post('/JSON/context/action/excludeFromContext/',
                   contextName=name, regex=regex)

    # ── Authentication ────────────────────────────────────────────────────────

    def set_auth_method(self, ctx_id: str, method: str, config: str = '') -> None:
        self._post('/JSON/authentication/action/setAuthenticationMethod/',
                   contextId=ctx_id,
                   authMethodName=method,
                   authMethodConfigParams=config)

    def set_logged_in_indicator(self, ctx_id: str, regex: str) -> None:
        self._post('/JSON/authentication/action/setLoggedInIndicator/',
                   contextId=ctx_id, loggedInIndicatorRegex=regex)

    def set_logged_out_indicator(self, ctx_id: str, regex: str) -> None:
        self._post('/JSON/authentication/action/setLoggedOutIndicator/',
                   contextId=ctx_id, loggedOutIndicatorRegex=regex)

    # ── Session management ────────────────────────────────────────────────────

    def set_session_mgmt(self, ctx_id: str, method: str) -> None:
        self._post('/JSON/sessionManagement/action/setSessionManagementMethod/',
                   contextId=ctx_id, methodName=method)

    # ── Users ─────────────────────────────────────────────────────────────────

    def new_user(self, ctx_id: str, name: str) -> str:
        return self._post('/JSON/users/action/newUser/',
                          contextId=ctx_id, name=name)['userId']

    def set_user_creds(self, ctx_id: str, user_id: str, creds: str) -> None:
        self._post('/JSON/users/action/setAuthenticationCredentials/',
                   contextId=ctx_id,
                   userId=user_id,
                   authCredentialsConfigParams=creds)

    def set_user_enabled(self, ctx_id: str, user_id: str, enabled: bool = True) -> None:
        self._post('/JSON/users/action/setUserEnabled/',
                   contextId=ctx_id,
                   userId=user_id,
                   enabled='true' if enabled else 'false')

    # ── Forced user ───────────────────────────────────────────────────────────

    def set_forced_user(self, ctx_id: str, user_id: str) -> None:
        self._post('/JSON/forcedUser/action/setForcedUser/',
                   contextId=ctx_id, userId=user_id)

    def forced_user_mode(self, enabled: bool) -> None:
        self._post('/JSON/forcedUser/action/setForcedUserModeEnabled/',
                   boolean='true' if enabled else 'false')

    # ── Reports ───────────────────────────────────────────────────────────────

    def generate_report(self, title: str, template: str,
                        filename: str, report_dir: str) -> dict:
        return self._post('/JSON/reports/action/generate/',
                          title=title,
                          template=template,
                          reportFileName=filename,
                          reportDir=report_dir)

    # ── Readiness ─────────────────────────────────────────────────────────────

    def wait_ready(self, timeout: int = 180, interval: int = 5) -> bool:
        print('Waiting for ZAP daemon...', flush=True)
        for i in range(timeout // interval):
            try:
                v = self.version()
                print(f'ZAP {v} is ready.', flush=True)
                return True
            except Exception:
                elapsed = i * interval
                print(f'  [{elapsed}s] not ready yet...', flush=True)
                time.sleep(interval)
        print('ERROR: ZAP did not respond in time.', flush=True)
        return False
