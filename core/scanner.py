"""
Main Scanner — Orchestrates all scanning modules.
"""

import time
import requests
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from core.config import (
    SENSITIVE_FILES, REQUEST_TIMEOUT,
    USER_AGENT, SEVERITY_SCORE, VERDICT_THRESHOLDS,
)
from core.crawler       import WebCrawler, CrawlResult
from core.headers_check import HeadersChecker, HeadersResult
from core.sqli          import SQLiScanner
from core.xss           import XSSScanner


# ── Data Classes ──────────────────────────────────────────────────────────────

@dataclass
class SensitiveFileFinding:
    url:         str
    status_code: int
    severity:    str = "HIGH"
    description: str = "Sensitive file exposed"


@dataclass
class ScanResult:
    target:            str
    crawl:             object = None
    headers:           object = None
    sqli_findings:     list   = field(default_factory=list)
    xss_findings:      list   = field(default_factory=list)
    redirect_findings: list   = field(default_factory=list)
    sensitive_files:   list   = field(default_factory=list)
    total_score:       int    = 0
    verdict:           str    = "SECURE"
    risk_level:        str    = "LOW"
    total_findings:    int    = 0
    scan_time:         float  = 0.0
    error:             str    = ""


# ── Main Scanner ──────────────────────────────────────────────────────────────

class WebVulnScanner:

    def __init__(self, target: str, skip_sqli: bool = False,
                 skip_xss: bool = False, verbose: bool = False,
                 cookie: str = ""):
        self.target    = target.rstrip("/")
        self.skip_sqli = skip_sqli
        self.skip_xss  = skip_xss
        self.verbose   = verbose
        self.cookie    = cookie
        self.parsed    = urlparse(self.target)
        self.session   = self._make_session()

    def scan(self) -> ScanResult:
        result = ScanResult(target=self.target)
        start  = time.time()

        # ── Step 1: Crawl ─────────────────────────────────────────────────────
        crawler      = WebCrawler(self.target, cookie=self.cookie)
        result.crawl = crawler.crawl()

        # ── Step 2: Headers ───────────────────────────────────────────────────
        checker        = HeadersChecker()
        result.headers = checker.check(self.target)

        # ── Step 3: Sensitive Files ───────────────────────────────────────────
        result.sensitive_files = self._check_sensitive_files()

        # ── Step 4: SQLi ──────────────────────────────────────────────────────
        if not self.skip_sqli:
            sqli = SQLiScanner(cookie=self.cookie)

            for url in result.crawl.params:
                r = sqli.scan_url(url)
                result.sqli_findings.extend(r.findings)

            for form in result.crawl.forms:
                r = sqli.scan_form(form, self.target)
                result.sqli_findings.extend(r.findings)

        # ── Step 5: XSS ───────────────────────────────────────────────────────
        if not self.skip_xss:
            xss = XSSScanner(cookie=self.cookie)

            for url in result.crawl.params:
                r = xss.scan_url(url)
                result.xss_findings.extend(r.xss_findings)
                result.redirect_findings.extend(r.redirect_findings)

            for form in result.crawl.forms:
                r = xss.scan_form(form, self.target)
                result.xss_findings.extend(r.xss_findings)
                result.redirect_findings.extend(r.redirect_findings)

        # ── Step 6: Score & Verdict ───────────────────────────────────────────
        result            = self._calculate_verdict(result)
        result.scan_time  = round(time.time() - start, 2)

        return result

    # ── Sensitive Files ───────────────────────────────────────────────────────

    def _check_sensitive_files(self) -> list:
        findings = []
        base     = f"{self.parsed.scheme}://{self.parsed.netloc}"

        for path in SENSITIVE_FILES:
            url = urljoin(base, path)
            try:
                resp = self.session.get(
                    url,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=False,
                    verify=False,
                )
                if resp.status_code in (200, 403):
                    sev  = "CRITICAL" if resp.status_code == 200 else "MEDIUM"
                    desc = (
                        f"File accessible: {path}"
                        if resp.status_code == 200
                        else f"File exists but forbidden: {path}"
                    )
                    findings.append(SensitiveFileFinding(
                        url         = url,
                        status_code = resp.status_code,
                        severity    = sev,
                        description = desc,
                    ))
                time.sleep(0.1)
            except requests.RequestException:
                continue
        return findings

    # ── Verdict ───────────────────────────────────────────────────────────────

    def _calculate_verdict(self, result: ScanResult) -> ScanResult:
        score = 0

        for _ in result.sqli_findings:
            score += SEVERITY_SCORE.get("CRITICAL", 40)

        for _ in result.xss_findings:
            score += SEVERITY_SCORE.get("HIGH", 25)

        for _ in result.redirect_findings:
            score += SEVERITY_SCORE.get("MEDIUM", 15)

        for f in result.sensitive_files:
            score += SEVERITY_SCORE.get(f.severity, 15)

        if result.headers:
            for f in result.headers.findings:
                if not f.present:
                    score += SEVERITY_SCORE.get(f.severity, 5)
            if result.headers.cors_misconfigured:
                score += SEVERITY_SCORE.get("HIGH", 25)
            if result.headers.clickjacking_vulnerable:
                score += SEVERITY_SCORE.get("MEDIUM", 15)
            for cf in result.headers.cookie_findings:
                score += SEVERITY_SCORE.get(cf.severity, 10)

        result.total_score = min(score, 100)
        result.total_findings = (
            len(result.sqli_findings)
            + len(result.xss_findings)
            + len(result.redirect_findings)
            + len(result.sensitive_files)
        )

        if result.total_score >= VERDICT_THRESHOLDS["VULNERABLE"]:
            result.verdict    = "VULNERABLE"
            result.risk_level = "CRITICAL" if result.total_score >= 80 else "HIGH"
        elif result.total_score >= VERDICT_THRESHOLDS["MODERATE"]:
            result.verdict    = "MODERATE"
            result.risk_level = "MEDIUM"
        else:
            result.verdict    = "SECURE"
            result.risk_level = "LOW"

        return result

    # ── Session ───────────────────────────────────────────────────────────────

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
                    s.cookies.set(
                        name.strip(), value.strip(),
                        domain=self.parsed.netloc,
                    )
        return s