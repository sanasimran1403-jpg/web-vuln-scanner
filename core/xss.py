"""
XSS Scanner — Tests forms and URL parameters for Cross-Site Scripting.
"""

import time
import requests
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.config import (
    XSS_PAYLOADS, OPEN_REDIRECT_PAYLOADS,
    REDIRECT_PARAMS, REQUEST_TIMEOUT, USER_AGENT,
)


# ── Data Classes ──────────────────────────────────────────────────────────────

@dataclass
class XSSFinding:
    url:         str
    parameter:   str
    payload:     str
    method:      str = "GET"
    severity:    str = "HIGH"
    description: str = "Cross-Site Scripting (XSS) vulnerability detected"


@dataclass
class RedirectFinding:
    url:         str
    parameter:   str
    payload:     str
    severity:    str = "MEDIUM"
    description: str = "Open Redirect vulnerability detected"


@dataclass
class XSSResult:
    xss_findings:      list = field(default_factory=list)
    redirect_findings: list = field(default_factory=list)
    tested:            int  = 0
    error:             str  = ""


# ── Scanner ───────────────────────────────────────────────────────────────────

class XSSScanner:

    def __init__(self, cookie: str = ""):
        self.cookie  = cookie
        self.session = self._make_session()

    def _make_session(self) -> requests.Session:
        s = requests.Session()
        s.headers.update({
            "User-Agent": USER_AGENT,
            "Accept":     "text/html,application/xhtml+xml,*/*",
        })
        if self.cookie:
            for part in self.cookie.split(";"):
                part = part.strip()
                if "=" in part:
                    name, value = part.split("=", 1)
                    s.cookies.set(name.strip(), value.strip())
        return s

    def scan_url(self, url: str) -> XSSResult:
        result = XSSResult()
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return result

        for param in params:
            # XSS Test
            for payload in XSS_PAYLOADS:
                result.tested += 1
                try:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload

                    new_query = urlencode(test_params)
                    test_url  = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, ""
                    ))

                    resp = self.session.get(
                        test_url,
                        timeout=REQUEST_TIMEOUT,
                        allow_redirects=True,
                        verify=False,
                    )

                    if self._xss_reflected(payload, resp.text):
                        result.xss_findings.append(XSSFinding(
                            url       = url,
                            parameter = param,
                            payload   = payload,
                            method    = "GET",
                        ))
                        break

                except requests.RequestException:
                    continue
                finally:
                    time.sleep(0.2)

            # Open Redirect Test
            if param.lower() in REDIRECT_PARAMS:
                for payload in OPEN_REDIRECT_PAYLOADS:
                    result.tested += 1
                    try:
                        test_params = {k: v[0] for k, v in params.items()}
                        test_params[param] = payload

                        new_query = urlencode(test_params)
                        test_url  = urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, new_query, ""
                        ))

                        resp = self.session.get(
                            test_url,
                            timeout=REQUEST_TIMEOUT,
                            allow_redirects=False,
                            verify=False,
                        )

                        if self._is_redirect(resp, payload):
                            result.redirect_findings.append(RedirectFinding(
                                url       = url,
                                parameter = param,
                                payload   = payload,
                            ))
                            break

                    except requests.RequestException:
                        continue
                    finally:
                        time.sleep(0.2)

        return result

    def scan_form(self, form, base_url: str) -> XSSResult:
        result = XSSResult()

        for field_obj in form.fields:
            if field_obj.field_type in ("submit", "hidden", "button", "image"):
                continue

            for payload in XSS_PAYLOADS:
                result.tested += 1
                try:
                    data = {f.name: f.value for f in form.fields}
                    data[field_obj.name] = payload

                    if form.method == "POST":
                        resp = self.session.post(
                            form.action,
                            data=data,
                            timeout=REQUEST_TIMEOUT,
                            allow_redirects=True,
                            verify=False,
                        )
                    else:
                        resp = self.session.get(
                            form.action,
                            params=data,
                            timeout=REQUEST_TIMEOUT,
                            allow_redirects=True,
                            verify=False,
                        )

                    if self._xss_reflected(payload, resp.text):
                        result.xss_findings.append(XSSFinding(
                            url       = form.action,
                            parameter = field_obj.name,
                            payload   = payload,
                            method    = form.method,
                        ))
                        break

                except requests.RequestException:
                    continue
                finally:
                    time.sleep(0.2)

        return result

    def _xss_reflected(self, payload: str, body: str) -> bool:
        return payload in body or payload.lower() in body.lower()

    def _is_redirect(self, resp: requests.Response, payload: str) -> bool:
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            return "evil.com" in location or payload in location
        return False
    

# cd D:\web-vuln-scanner

# python main.py scan "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie "PHPSESSID=0tsa60b3nvd8asn4kpgf89mfc5; security=low"
# python main.py scan "http://localhost/vulnerabilities/xss_r/?name=test" --cookie "PHPSESSID=0tsa60b3nvd8asn4kpgf89mfc5; security=low"