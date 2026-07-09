# Web Vulnerability Scanner

A Python-based CLI web vulnerability scanner that crawls target URLs and actively tests for common web security flaws — SQL Injection, XSS, Open Redirect, missing security headers, and sensitive file exposure. Supports authenticated scanning via cookie injection.

## Overview

Web application vulnerabilities remain the most common attack surface in real-world breaches. This tool demonstrates the full black-box scanning pipeline a penetration tester would run against a web target:

1. **Crawl** the target — discover all pages, forms, and parameters automatically
2. **Test Headers** — check for missing or misconfigured security headers (CSP, HSTS, X-Frame-Options)
3. **Inject SQLi** — test every parameter for error-based SQL Injection
4. **Inject XSS** — test every input field for reflected Cross-Site Scripting
5. **Test Redirects** — detect Open Redirect vulnerabilities in URL parameters
6. **Report** — generate a professional dark-themed PDF with all findings and evidence

All modules were tested end-to-end against DVWA (Damn Vulnerable Web Application) in an isolated local lab, not just run on synthetic examples.

**Environment:**
- Platform: Windows 11 + Python 3.11
- Target: DVWA running on localhost (Apache/MySQL)
- Auth: Cookie-based session injection for authenticated scanning

## Feature Coverage — 5/5

| # | Feature | Technique | Result |
|---|---|---|---|
| 1 | Web Crawling | Recursive link discovery, form extraction | Full site map built |
| 2 | Security Headers | CSP, HSTS, X-Frame-Options, X-Content-Type check | Missing headers flagged |
| 3 | SQL Injection | Error-based detection via crafted payloads | CRITICAL — SQLi confirmed on DVWA |
| 4 | XSS Detection | Reflected XSS via script injection payloads | HIGH — XSS confirmed on DVWA |
| 5 | Open Redirect | URL parameter manipulation testing | Redirect vulnerabilities detected |

## Setup

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan (unauthenticated)
python main.py scan --url http://target.com

# Authenticated scan with session cookie
python main.py scan --url http://localhost/dvwa --cookie "PHPSESSID=abc123;security=low"

# Scan specific modules only
python main.py scan --url http://target.com --modules sqli,xss,headers

# View scan history
python main.py history

# Generate PDF report for last scan
python main.py report --id 1
```

## 1. Web Crawling

**Command:**
```bash
python main.py scan --url http://localhost/dvwa --cookie "PHPSESSID=abc123;security=low"
```

Crawling logic: recursively discovers all internal links, extracts all HTML forms and input fields, identifies URL parameters for injection testing, and respects same-domain scope to avoid crawling external sites.

**Result:** Full site map built — 12 pages discovered, 8 forms extracted, 24 parameters queued for injection testing.

## 2. Security Headers Check

**Command:**
```bash
# Runs automatically as part of every scan
python main.py scan --url http://target.com
```

Detection logic: sends an HTTP GET to the target root and inspects response headers for the presence and correct configuration of Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy.

**Result:**
```
Content-Security-Policy  : MISSING
Strict-Transport-Security: MISSING
X-Frame-Options          : MISSING
X-Content-Type-Options   : MISSING
Header Risk              : HIGH
```

## 3. SQL Injection

**Command:**
```bash
python main.py scan --url http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit \
  --cookie "PHPSESSID=abc123;security=low"
```

Detection logic: appends error-based SQLi payloads (`'`, `''`, `' OR '1'='1`, `1' AND 1=2--`) to every discovered parameter and inspects responses for database error signatures (MySQL, MSSQL, PostgreSQL, Oracle).

**Result:**
```
URL      : http://localhost/vulnerabilities/sqli/?id=1
Parameter: id
Payload  : '
Evidence : You have an error in your SQL syntax
Risk     : CRITICAL
```

## 4. Cross-Site Scripting (XSS)

**Command:**
```bash
python main.py scan --url http://localhost/vulnerabilities/xss_r/?name=test \
  --cookie "PHPSESSID=abc123;security=low"
```

Detection logic: injects XSS payloads (`<script>alert('XSS')</script>`, `<img src=x onerror=alert(1)>`) into all form inputs and URL parameters, then checks if the payload is reflected unsanitized in the response body.

**Result:**
```
URL      : http://localhost/vulnerabilities/xss_r/
Parameter: name
Payload  : <script>alert('XSS')</script>
Evidence : Payload reflected in response
Risk     : HIGH
```

## 5. Open Redirect

Detection logic: replaces URL parameter values with external domains (`https://evil.com`) and follows redirects to detect if the application blindly redirects users to attacker-controlled URLs.

**Result:**
```
URL      : http://localhost/redirect?url=https://evil.com
Evidence : 302 redirect to https://evil.com confirmed
Risk     : MEDIUM
```

## Repository Structure

```
web-vuln-scanner/
├── main.py
├── requirements.txt
├── README.md
├── .env.example
├── core/
│   ├── config.py
│   ├── crawler.py         # Recursive link + form discovery
│   ├── headers_check.py   # Security headers analysis
│   ├── sqli.py            # SQL Injection detection
│   ├── xss.py             # XSS detection
│   ├── scanner.py         # Scan orchestration
│   ├── database.py        # SQLite scan history
│   └── reporter.py        # Dark-themed PDF report generator
└── data/
    └── scans.db
```

## Tech Stack

| Tool | Version | Purpose |
|---|---|---|
| Python | 3.11 | Core language |
| requests | 2.31 | HTTP requests + session handling |
| BeautifulSoup4 | 4.12 | HTML parsing + form extraction |
| Rich | 13.7 | CLI output formatting |
| ReportLab | 4.1.0 | Dark-themed PDF reports |
| SQLite | built-in | Scan history storage |

## Key Learnings

- Building a recursive web crawler that correctly handles relative URLs, query parameters, and form actions without going out of scope
- Implementing error-based SQLi detection by matching database error signatures across MySQL, MSSQL, PostgreSQL, and Oracle — without relying on sqlmap
- Designing reflected XSS detection that distinguishes between sanitized and unsanitized payload reflection in response bodies
- Adding cookie injection support to enable authenticated scanning of login-protected pages
- Understanding why security header misconfiguration is consistently in the OWASP Top 10 and how to detect it programmatically

## Known Limitations

- Only error-based SQLi is detected — blind/time-based SQLi requires significantly longer scan times and is not yet implemented
- XSS detection covers reflected XSS only — stored and DOM-based XSS require different detection approaches
- The crawler respects same-domain scope only — subdomain crawling is not yet supported
- JavaScript-heavy SPAs (React, Angular, Vue) are not fully crawled — only static HTML links and forms are discovered

## Author

**Sana Simran**
GitHub: [@sanasimran1403-jpg](https://github.com/sanasimran1403-jpg)

> **Disclaimer:** This tool is intended for authorized penetration testing and security research only. Never scan targets you do not own or have explicit written permission to test.
