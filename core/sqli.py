"""
SQL Injection Scanner — Tests forms and URL parameters for SQLi vulnerabilities.
"""

import time
import requests
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.config import (
    SQLI_PAYLOADS, SQLI_ERRORS,
    REQUEST_TIMEOUT, USER_AGENT,
)


# ── Data Classes ──────────────────────────────────────────────────────────────

@dataclass
class SQLiFinding:
    url:         str
    parameter:   str
    payload:     str
    evidence:    str
    method:      str = "GET"
    severity:    str = "CRITICAL"
    description: str = "SQL Injection vulnerability detected"


@dataclass
class SQLiResult:
    findings:  list = field(default_factory=list)
    tested:    int  = 0
    error:     str  = ""


# ── Scanner ───────────────────────────────────────────────────────────────────

class SQLiScanner:

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
            parsed = urlparse("")
            for part in self.cookie.split(";"):
                part = part.strip()
                if "=" in part:
                    name, value = part.split("=", 1)
                    s.cookies.set(name.strip(), value.strip())
        return s

    def scan_url(self, url: str) -> SQLiResult:
        result = SQLiResult()
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return result

        for param in params:
            for payload in SQLI_PAYLOADS:
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

                    evidence = self._check_response(resp.text)
                    if evidence:
                        result.findings.append(SQLiFinding(
                            url       = url,
                            parameter = param,
                            payload   = payload,
                            evidence  = evidence,
                            method    = "GET",
                        ))
                        break

                except requests.RequestException:
                    continue
                finally:
                    time.sleep(0.2)

        return result

    def scan_form(self, form, base_url: str) -> SQLiResult:
        result = SQLiResult()

        for field_obj in form.fields:
            if field_obj.field_type in ("hidden", "button", "image"):
                continue

            for payload in SQLI_PAYLOADS:
                result.tested += 1
                try:
                    data = {f.name: f.value for f in form.fields}
                    if "Submit" not in data:
                        data["Submit"] = "Submit"
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

                    evidence = self._check_response(resp.text)
                    if evidence:
                        result.findings.append(SQLiFinding(
                            url       = form.action,
                            parameter = field_obj.name,
                            payload   = payload,
                            evidence  = evidence,
                            method    = form.method,
                        ))
                        break

                except requests.RequestException:
                    continue
                finally:
                    time.sleep(0.2)

        return result

    def _check_response(self, body: str) -> str:
        body_lower = body.lower()
        for error in SQLI_ERRORS:
            if error.lower() in body_lower:
                idx   = body_lower.find(error.lower())
                start = max(0, idx - 30)
                end   = min(len(body), idx + len(error) + 60)
                return body[start:end].strip()
        return ""