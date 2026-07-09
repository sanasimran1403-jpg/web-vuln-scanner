"""
Database — SQLite scan history for Web Vulnerability Scanner.
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path

from core.config import DB_PATH


class Database:

    def __init__(self):
        Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at      TEXT    NOT NULL,
                target          TEXT,
                pages_crawled   INTEGER,
                forms_found     INTEGER,
                total_findings  INTEGER,
                sqli_count      INTEGER,
                xss_count       INTEGER,
                redirect_count  INTEGER,
                sensitive_count INTEGER,
                score           INTEGER,
                verdict         TEXT,
                risk_level      TEXT,
                scan_time       REAL,
                report_path     TEXT
            );

            CREATE TABLE IF NOT EXISTS findings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     INTEGER REFERENCES scans(id),
                category    TEXT,
                severity    TEXT,
                url         TEXT,
                parameter   TEXT,
                payload     TEXT,
                description TEXT
            );
        """)
        self.conn.commit()

    def save_scan(self, result, report_path: str = "") -> int:
        cursor = self.conn.execute(
            """
            INSERT INTO scans
              (scanned_at, target, pages_crawled, forms_found,
               total_findings, sqli_count, xss_count, redirect_count,
               sensitive_count, score, verdict, risk_level,
               scan_time, report_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.utcnow().isoformat(),
                result.target,
                len(result.crawl.pages)  if result.crawl  else 0,
                len(result.crawl.forms)  if result.crawl  else 0,
                result.total_findings,
                len(result.sqli_findings),
                len(result.xss_findings),
                len(result.redirect_findings),
                len(result.sensitive_files),
                result.total_score,
                result.verdict,
                result.risk_level,
                result.scan_time,
                report_path,
            ),
        )
        scan_id = cursor.lastrowid

        # Save individual findings
        for f in result.sqli_findings:
            self._save_finding(scan_id, "SQLi", "CRITICAL",
                               f.url, f.parameter, f.payload, f.description)

        for f in result.xss_findings:
            self._save_finding(scan_id, "XSS", "HIGH",
                               f.url, f.parameter, f.payload, f.description)

        for f in result.redirect_findings:
            self._save_finding(scan_id, "Open Redirect", "MEDIUM",
                               f.url, f.parameter, f.payload, f.description)

        for f in result.sensitive_files:
            self._save_finding(scan_id, "Sensitive File", f.severity,
                               f.url, "", "", f.description)

        if result.headers:
            for f in result.headers.findings:
                if not f.present:
                    self._save_finding(scan_id, "Missing Header", f.severity,
                                       result.target, f.header, "", f.description)

        self.conn.commit()
        return scan_id

    def _save_finding(self, scan_id, category, severity,
                      url, parameter, payload, description):
        self.conn.execute(
            """
            INSERT INTO findings
              (scan_id, category, severity, url, parameter, payload, description)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (scan_id, category, severity, url,
             parameter, payload, description),
        )

    def get_recent_scans(self, limit: int = 10) -> list:
        cursor = self.conn.execute(
            "SELECT * FROM scans ORDER BY scanned_at DESC LIMIT ?", (limit,)
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_stats(self) -> dict:
        cursor = self.conn.execute("""
            SELECT
                COUNT(*)  as total,
                SUM(CASE WHEN verdict='VULNERABLE' THEN 1 ELSE 0 END) as vulnerable,
                SUM(CASE WHEN verdict='MODERATE'   THEN 1 ELSE 0 END) as moderate,
                SUM(CASE WHEN verdict='SECURE'     THEN 1 ELSE 0 END) as secure,
                SUM(sqli_count)      as total_sqli,
                SUM(xss_count)       as total_xss,
                SUM(sensitive_count) as total_sensitive
            FROM scans
        """)
        row = cursor.fetchone()
        return dict(row) if row else {}

    def close(self):
        self.conn.close()