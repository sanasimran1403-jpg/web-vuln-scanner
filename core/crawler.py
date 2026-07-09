"""
Web Crawler — Discovers pages, forms, and parameters on target website.
"""

import re
import time
from urllib.parse import urljoin, urlparse, urlencode, parse_qs
from dataclasses import dataclass, field
from typing import Optional
from collections import deque

import requests
from bs4 import BeautifulSoup

from core.config import (
    MAX_DEPTH, MAX_PAGES, REQUEST_TIMEOUT,
    MAX_RETRIES, USER_AGENT,
)


# ── Data Classes ──────────────────────────────────────────────────────────────

@dataclass
class FormField:
    name:         str
    field_type:   str = "text"
    value:        str = ""


@dataclass
class Form:
    action:  str
    method:  str
    fields:  list = field(default_factory=list)


@dataclass
class CrawlResult:
    base_url:    str
    pages:       list = field(default_factory=list)
    forms:       list = field(default_factory=list)
    params:      list = field(default_factory=list)
    assets:      list = field(default_factory=list)
    errors:      list = field(default_factory=list)
    status_code: int  = 0
    server:      str  = ""
    tech_stack:  list = field(default_factory=list)


# ── Crawler ───────────────────────────────────────────────────────────────────

class WebCrawler:

    def __init__(self, base_url: str, cookie: str = "", verbose: bool = False):
        self.base_url    = base_url.rstrip("/")
        self.parsed      = urlparse(self.base_url)
        self.base_domain = self.parsed.netloc
        self.cookie      = cookie
        self.verbose     = verbose
        self.session     = self._make_session()

    def crawl(self) -> CrawlResult:
        result = CrawlResult(base_url=self.base_url)

        try:
            resp = self._get(self.base_url)
            if resp:
                result.status_code = resp.status_code
                result.server      = resp.headers.get("Server", "")
                result.tech_stack  = self._detect_tech(resp)
        except Exception as e:
            result.errors.append(str(e))
            return result

        queue   = deque([(self.base_url, 0)])
        visited = set()

        from urllib.parse import urlparse, parse_qs
        if "?" in self.base_url:
            result.params.append(self.base_url)

        while queue and len(result.pages) < MAX_PAGES:
            url, depth = queue.popleft()

            if url in visited or depth > MAX_DEPTH:
                continue
            visited.add(url)

            try:
                resp = self._get(url)
                if not resp or resp.status_code >= 400:
                    continue

                result.pages.append(url)
                soup = BeautifulSoup(resp.text, "lxml")

                for form in soup.find_all("form"):
                    parsed_form = self._parse_form(form, url)
                    if parsed_form:
                        result.forms.append(parsed_form)

                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    full = urljoin(url, href)
                    full = full.split("#")[0]

                    if not self._is_same_domain(full):
                        continue
                    if full in visited:
                        continue

                    if "?" in full and full not in result.params:
                        result.params.append(full)

                    queue.append((full, depth + 1))

            except Exception as e:
                result.errors.append(f"{url}: {str(e)[:80]}")

        return result

    def _get(self, url: str) -> Optional[requests.Response]:
        for attempt in range(MAX_RETRIES + 1):
            try:
                resp = self.session.get(
                    url,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                )
                return resp
            except requests.RequestException:
                if attempt == MAX_RETRIES:
                    return None
                time.sleep(1)
        return None

    def _make_session(self) -> requests.Session:
        s = requests.Session()
        s.headers.update({
            "User-Agent":      USER_AGENT,
            "Accept":          "text/html,application/xhtml+xml,*/*",
            "Accept-Language": "en-US,en;q=0.9",
        })
        if self.cookie:
            for part in self.cookie.split(";"):
                part = part.strip()
                if "=" in part:
                    name, value = part.split("=", 1)
                    s.cookies.set(name.strip(), value.strip(),
                                  domain=self.parsed.netloc)
        return s

    def _is_same_domain(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            return (
                parsed.scheme in ("http", "https")
                and parsed.netloc == self.base_domain
            )
        except Exception:
            return False

    def _parse_form(self, form_tag, page_url: str) -> Optional[Form]:
        action = form_tag.get("action", "")
        method = form_tag.get("method", "get").upper()
        action = urljoin(page_url, action) if action else page_url

        fields = []
        for inp in form_tag.find_all(["input", "textarea", "select"]):
            name  = inp.get("name", "")
            ftype = inp.get("type", "text")
            value = inp.get("value", "test")
            if name:
                fields.append(FormField(name=name, field_type=ftype, value=value))

        if not fields:
            return None

        return Form(action=action, method=method, fields=fields)

    def _detect_tech(self, resp: requests.Response) -> list:
        tech    = []
        server  = resp.headers.get("Server", "").lower()
        powered = resp.headers.get("X-Powered-By", "").lower()
        body    = resp.text.lower()

        checks = [
            (server,  "apache",     "Apache"),
            (server,  "nginx",      "Nginx"),
            (server,  "iis",        "IIS"),
            (powered, "php",        "PHP"),
            (powered, "asp.net",    "ASP.NET"),
            (body,    "wp-content", "WordPress"),
            (body,    "joomla",     "Joomla"),
            (body,    "drupal",     "Drupal"),
            (body,    "laravel",    "Laravel"),
            (body,    "django",     "Django"),
            (body,    "react",      "React"),
            (body,    "angular",    "Angular"),
        ]

        for source, keyword, label in checks:
            if keyword in source:
                tech.append(label)

        return tech