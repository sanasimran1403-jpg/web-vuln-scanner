"""
Headers & Cookie Security Checker
"""

import requests
from dataclasses import dataclass, field
from core.config import SECURITY_HEADERS, COOKIE_FLAGS, USER_AGENT, REQUEST_TIMEOUT


# ── Data Classes ──────────────────────────────────────────────────────────────

@dataclass
class HeaderFinding:
    header:      str
    severity:    str
    description: str
    present:     bool = False
    value:       str  = ""


@dataclass
class CookieFinding:
    name:        str
    missing_flags: list = field(default_factory=list)
    severity:    str = "MEDIUM"


@dataclass
class HeadersResult:
    url:              str
    findings:         list = field(default_factory=list)
    cookie_findings:  list = field(default_factory=list)
    server_info:      str  = ""
    cors_misconfigured: bool = False
    cors_detail:      str  = ""
    clickjacking_vulnerable: bool = False
    error:            str  = ""


# ── Checker ───────────────────────────────────────────────────────────────────

class HeadersChecker:
    """
    Checks HTTP response headers and cookies for security misconfigurations.
    """

    def check(self, url: str) -> HeadersResult:
        result = HeadersResult(url=url)

        try:
            resp = requests.get(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                headers={"User-Agent": USER_AGENT},
                verify=False,
            )
        except requests.RequestException as e:
            result.error = str(e)
            return result

        headers = resp.headers
        result.server_info = headers.get("Server", "Not disclosed")

        # ── Security Headers ──────────────────────────────────────────────────
        for header_name, meta in SECURITY_HEADERS.items():
            value   = headers.get(header_name, "")
            present = bool(value)
            finding = HeaderFinding(
                header      = header_name,
                severity    = meta["severity"] if not present else "INFO",
                description = meta["description"] if not present else f"Present: {value[:80]}",
                present     = present,
                value       = value,
            )
            result.findings.append(finding)

        # ── Clickjacking ──────────────────────────────────────────────────────
        xfo = headers.get("X-Frame-Options", "").upper()
        csp = headers.get("Content-Security-Policy", "")
        if not xfo and "frame-ancestors" not in csp.lower():
            result.clickjacking_vulnerable = True

        # ── CORS Misconfiguration ─────────────────────────────────────────────
        acao = headers.get("Access-Control-Allow-Origin", "")
        acac = headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*":
            result.cors_misconfigured = True
            result.cors_detail = "Wildcard ACAO header — any origin allowed"
        elif acao and acac.lower() == "true":
            result.cors_misconfigured = True
            result.cors_detail = (
                f"CORS allows credentials from origin: {acao} — "
                "potential data leakage if origin is attacker-controlled"
            )

        # ── Cookie Analysis ───────────────────────────────────────────────────
        for cookie in resp.cookies:
            missing = []
            if not cookie.has_nonstandard_attr("HttpOnly") and not getattr(cookie, "_rest", {}).get("HttpOnly"):
                # Check via Set-Cookie header string
                sc_headers = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, "getlist") else []
                cookie_str = " ".join(sc_headers).lower()

                missing_flags = []
                cookie_lower  = cookie.name.lower()

                # Re-parse Set-Cookie from headers
                set_cookie_raw = resp.headers.get("Set-Cookie", "")
                if "httponly" not in set_cookie_raw.lower():
                    missing_flags.append("HttpOnly")
                if "secure" not in set_cookie_raw.lower():
                    missing_flags.append("Secure")
                if "samesite" not in set_cookie_raw.lower():
                    missing_flags.append("SameSite")

                if missing_flags:
                    sev = "HIGH" if "HttpOnly" in missing_flags else "MEDIUM"
                    result.cookie_findings.append(CookieFinding(
                        name=cookie.name,
                        missing_flags=missing_flags,
                        severity=sev,
                    ))

        return result