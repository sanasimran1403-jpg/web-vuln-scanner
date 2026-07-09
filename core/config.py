"""
Configuration & constants for Web Vulnerability Scanner
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ── Scanner Settings ──────────────────────────────────────────────────────────
MAX_DEPTH        = 3          # Crawler depth
MAX_PAGES        = 50         # Max pages to crawl
REQUEST_TIMEOUT  = 10         # seconds
MAX_RETRIES      = 2
THREADS          = 5          # Concurrent threads
USER_AGENT       = "Mozilla/5.0 (compatible; SS-WebScanner/1.0; Security Research)"

# ── Severity Weights ──────────────────────────────────────────────────────────
SEVERITY_SCORE = {
    "CRITICAL": 40,
    "HIGH":     25,
    "MEDIUM":   15,
    "LOW":       5,
    "INFO":      0,
}

# ── Verdict Thresholds ────────────────────────────────────────────────────────
VERDICT_THRESHOLDS = {
    "VULNERABLE":  60,
    "MODERATE":    25,
    "SECURE":       0,
}

# ── SQL Injection Payloads ────────────────────────────────────────────────────
SQLI_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "\" OR \"1\"=\"1",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "admin'--",
    "1; DROP TABLE users--",
]

SQLI_ERRORS = [
    "sql syntax",
    "mysql_fetch",
    "ora-01756",
    "microsoft ole db",
    "odbc microsoft access",
    "syntax error",
    "mysql_num_rows",
    "supplied argument is not a valid mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "postgresql",
    "warning: mysql",
    "you have an error in your sql syntax",
    "division by zero",
    "invalid query",
    "sql command not properly ended",
]

# ── XSS Payloads ──────────────────────────────────────────────────────────────
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "'><script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>",
    "<body onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "<<SCRIPT>alert('XSS')//<</SCRIPT>",
    "<IMG SRC=javascript:alert('XSS')>",
]

# ── Sensitive Files ───────────────────────────────────────────────────────────
SENSITIVE_FILES = [
    "/.env",
    "/.git/config",
    "/robots.txt",
    "/sitemap.xml",
    "/.htaccess",
    "/web.config",
    "/config.php",
    "/wp-config.php",
    "/phpinfo.php",
    "/admin/",
    "/administrator/",
    "/backup/",
    "/db/",
    "/sql/",
    "/.DS_Store",
    "/error_log",
    "/debug.log",
    "/config.yml",
    "/config.yaml",
    "/.env.backup",
    "/id_rsa",
]

# ── Security Headers ──────────────────────────────────────────────────────────
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "HSTS missing — site vulnerable to protocol downgrade attacks",
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "CSP missing — increases XSS attack surface",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "Clickjacking protection missing",
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": "MIME sniffing protection missing",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Referrer policy not set — may leak sensitive URLs",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": "Permissions policy not configured",
    },
    "X-XSS-Protection": {
        "severity": "LOW",
        "description": "Legacy XSS filter header missing",
    },
}

# ── Open Redirect Payloads ────────────────────────────────────────────────────
OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com%2F%2F",
    "/\\evil.com",
    "/%09/evil.com",
]

REDIRECT_PARAMS = [
    "redirect", "url", "next", "return",
    "returnUrl", "return_url", "goto",
    "destination", "redir", "redirect_uri",
    "callback", "continue", "forward",
]

# ── Cookie Flags ──────────────────────────────────────────────────────────────
COOKIE_FLAGS = ["HttpOnly", "Secure", "SameSite"]

# ── Database & Reports ────────────────────────────────────────────────────────
DB_PATH      = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "scans.db")
REPORTS_DIR  = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
LOGO_PATH    = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logo.png")