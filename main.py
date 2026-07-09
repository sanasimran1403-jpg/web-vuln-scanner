#!/usr/bin/env python3
"""
Web Vulnerability Scanner — Main CLI
Usage:
    python main.py scan <url>
    python main.py scan <url> --no-sqli --no-xss
    python main.py scan <url> --cookie "PHPSESSID=abc123;security=low"
    python main.py history
    python main.py stats
"""

import sys
import os
import argparse
import warnings
warnings.filterwarnings("ignore")

from rich.console  import Console
from rich.panel    import Panel
from rich.table    import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text     import Text
from rich.rule     import Rule
from rich          import box

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.scanner  import WebVulnScanner
from core.database import Database
from core.reporter import generate_report

console = Console()

VERDICT_STYLE = {
    "VULNERABLE": "bold red",
    "MODERATE":   "bold yellow",
    "SECURE":     "bold green",
}

SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "bold red",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold cyan",
    "INFO":     "bold green",
}


# ── Scan ──────────────────────────────────────────────────────────────────────

def cmd_scan(args):
    target = args.url
    if not target.startswith("http"):
        target = "http://" + target

    console.print()
    console.print(Panel.fit(
        "[bold cyan]🔍 Web Vulnerability Scanner[/bold cyan]\n"
        "[dim]S&S Security Research Tool[/dim]",
        border_style="cyan",
    ))
    console.print()
    console.print(f"[bold]Target:[/bold] [cyan]{target}[/cyan]")

    if args.cookie:
        console.print(f"[bold]Cookie:[/bold] [dim]{args.cookie[:50]}...[/dim]"
                      if len(args.cookie) > 50 else
                      f"[bold]Cookie:[/bold] [dim]{args.cookie}[/dim]")
    console.print()

    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        console=console,
    ) as progress:
        t1 = progress.add_task("🕷  Crawling target...",          total=None)
        t2 = progress.add_task("🛡  Checking security headers...", total=None)
        t3 = progress.add_task("📁  Scanning sensitive files...",  total=None)
        t4 = progress.add_task("💉  Testing SQL Injection...",     total=None)
        t5 = progress.add_task("⚡  Testing XSS...",               total=None)

        scanner = WebVulnScanner(
            target,
            skip_sqli = args.no_sqli,
            skip_xss  = args.no_xss,
            cookie    = args.cookie,
        )

        result = scanner.scan()

        progress.update(t1, description="[green]✓ Crawl complete[/green]")
        progress.update(t2, description="[green]✓ Headers checked[/green]")
        progress.update(t3, description="[green]✓ Sensitive files scanned[/green]")
        progress.update(t4, description="[dim]Skipped[/dim]" if args.no_sqli else "[green]✓ SQLi scan done[/green]")
        progress.update(t5, description="[dim]Skipped[/dim]" if args.no_xss  else "[green]✓ XSS scan done[/green]")

    _print_summary(result)
    _print_sqli(result)
    _print_xss(result)
    _print_redirects(result)
    _print_sensitive(result)
    _print_headers(result)
    _print_verdict(result)

    db = Database()
    try:
        scan_id     = db.save_scan(result)
        report_path = generate_report(result, scan_id)
        db.conn.execute(
            "UPDATE scans SET report_path=? WHERE id=?",
            (report_path, scan_id),
        )
        db.conn.commit()
        console.print(f"\n[dim]💾 Scan saved (ID #{scan_id})[/dim]")
        console.print(f"[dim]📄 Report:[/dim] {report_path}")
    finally:
        db.close()

    console.print()


# ── History ───────────────────────────────────────────────────────────────────

def cmd_history(args):
    db   = Database()
    rows = db.get_recent_scans(limit=args.limit)
    db.close()

    if not rows:
        console.print("[yellow]No scans yet.[/yellow]")
        return

    table = Table(title="📋 Recent Scans", box=box.ROUNDED, border_style="cyan")
    table.add_column("ID",       style="dim",     width=5)
    table.add_column("Date",     style="dim",      width=20)
    table.add_column("Target",   max_width=35)
    table.add_column("Findings", justify="center", width=10)
    table.add_column("Score",    justify="center", width=8)
    table.add_column("Verdict",  justify="center", width=12)
    table.add_column("Time",     justify="center", width=8)

    for row in rows:
        vs = VERDICT_STYLE.get(row["verdict"], "white")
        table.add_row(
            str(row["id"]),
            row["scanned_at"][:19],
            (row["target"] or "")[:35],
            str(row["total_findings"]),
            str(row["score"]),
            Text(row["verdict"], style=vs),
            f"{row['scan_time']}s",
        )

    console.print(table)


# ── Stats ─────────────────────────────────────────────────────────────────────

def cmd_stats(args):
    db    = Database()
    stats = db.get_stats()
    db.close()

    if not stats or not stats.get("total"):
        console.print("[yellow]No scan data yet.[/yellow]")
        return

    total = stats["total"]
    console.print()
    console.print(Panel.fit("[bold]📊 Scanner Statistics[/bold]", border_style="cyan"))

    table = Table(box=box.SIMPLE, show_header=False)
    table.add_column("Metric", style="bold")
    table.add_column("Value",  justify="right")

    table.add_row("Total Scans",       str(total))
    table.add_row("🔴 Vulnerable",      str(stats.get("vulnerable")      or 0))
    table.add_row("🟡 Moderate",        str(stats.get("moderate")        or 0))
    table.add_row("🟢 Secure",          str(stats.get("secure")          or 0))
    table.add_row("💉 SQLi Found",      str(stats.get("total_sqli")      or 0))
    table.add_row("⚡ XSS Found",       str(stats.get("total_xss")       or 0))
    table.add_row("📁 Sensitive Files", str(stats.get("total_sensitive") or 0))

    console.print(table)


# ── Print Helpers ─────────────────────────────────────────────────────────────

def _print_summary(result):
    console.print(Rule("[bold]Scan Summary[/bold]", style="dim"))
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    table.add_column("Key",   style="bold dim", width=18)
    table.add_column("Value")

    crawl = result.crawl
    table.add_row("Pages Crawled", str(len(crawl.pages))  if crawl else "0")
    table.add_row("Forms Found",   str(len(crawl.forms))  if crawl else "0")
    table.add_row("URL Params",    str(len(crawl.params)) if crawl else "0")
    table.add_row("Server",        crawl.server           if crawl and crawl.server else "N/A")
    table.add_row("Tech Stack",    ", ".join(crawl.tech_stack) if crawl and crawl.tech_stack else "N/A")
    table.add_row("Scan Time",     f"{result.scan_time}s")
    console.print(table)
    console.print()


def _print_sqli(result):
    console.print(Rule("[bold]SQL Injection[/bold]", style="dim"))
    if not result.sqli_findings:
        console.print("  [green]✓ No SQLi vulnerabilities found[/green]")
        console.print()
        return

    table = Table(box=box.SIMPLE, padding=(0, 1))
    table.add_column("Severity",  width=10)
    table.add_column("Parameter", width=15)
    table.add_column("Payload",   width=35)
    table.add_column("URL")

    for f in result.sqli_findings:
        table.add_row(
            Text("CRITICAL", style="bold red"),
            f.parameter,
            f.payload[:35],
            f.url[:50],
        )
    console.print(table)
    console.print()


def _print_xss(result):
    console.print(Rule("[bold]XSS[/bold]", style="dim"))
    if not result.xss_findings:
        console.print("  [green]✓ No XSS vulnerabilities found[/green]")
        console.print()
        return

    table = Table(box=box.SIMPLE, padding=(0, 1))
    table.add_column("Severity",  width=10)
    table.add_column("Method",    width=8)
    table.add_column("Parameter", width=15)
    table.add_column("URL")

    for f in result.xss_findings:
        table.add_row(
            Text("HIGH", style="bold red"),
            f.method,
            f.parameter,
            f.url[:55],
        )
    console.print(table)
    console.print()


def _print_redirects(result):
    if not result.redirect_findings:
        return
    console.print(Rule("[bold]Open Redirect[/bold]", style="dim"))
    table = Table(box=box.SIMPLE, padding=(0, 1))
    table.add_column("Severity",  width=10)
    table.add_column("Parameter", width=15)
    table.add_column("URL")

    for f in result.redirect_findings:
        table.add_row(
            Text("MEDIUM", style="bold yellow"),
            f.parameter,
            f.url[:60],
        )
    console.print(table)
    console.print()


def _print_sensitive(result):
    console.print(Rule("[bold]Sensitive Files[/bold]", style="dim"))
    if not result.sensitive_files:
        console.print("  [green]✓ No sensitive files exposed[/green]")
        console.print()
        return

    table = Table(box=box.SIMPLE, padding=(0, 1))
    table.add_column("Severity", width=10)
    table.add_column("Status",   width=8)
    table.add_column("URL")

    for f in result.sensitive_files:
        style = "bold red" if f.severity == "CRITICAL" else "bold yellow"
        table.add_row(
            Text(f.severity, style=style),
            str(f.status_code),
            f.url,
        )
    console.print(table)
    console.print()


def _print_headers(result):
    console.print(Rule("[bold]Security Headers[/bold]", style="dim"))
    if not result.headers or not result.headers.findings:
        console.print("  [dim]No header data[/dim]")
        console.print()
        return

    table = Table(box=box.SIMPLE, padding=(0, 1))
    table.add_column("Status",   width=10)
    table.add_column("Header",   width=32)
    table.add_column("Severity", width=10)

    for f in result.headers.findings:
        if f.present:
            table.add_row(
                Text("PRESENT", style="bold green"),
                f.header,
                Text("INFO", style="bold green"),
            )
        else:
            style = SEVERITY_STYLE.get(f.severity, "white")
            table.add_row(
                Text("MISSING", style=style),
                f.header,
                Text(f.severity, style=style),
            )

    console.print(table)

    if result.headers.cors_misconfigured:
        console.print(
            f"  [bold red]⚠ CORS:[/bold red] {result.headers.cors_detail}"
        )
    console.print()


def _print_verdict(result):
    style = VERDICT_STYLE.get(result.verdict, "white")
    icons = {
        "VULNERABLE": "🔴",
        "MODERATE":   "🟡",
        "SECURE":     "🟢",
    }
    icon = icons.get(result.verdict, "")

    console.print(Panel(
        f"[{style}]{icon}  VERDICT: {result.verdict}[/{style}]\n"
        f"Risk Score: [bold]{result.total_score}/100[/bold]  |  "
        f"Risk Level: [bold]{result.risk_level}[/bold]  |  "
        f"Total Findings: [bold]{result.total_findings}[/bold]",
        border_style=style.replace("bold ", ""),
        title="Final Analysis",
    ))


# ── Entry Point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="web-vuln-scanner",
        description="Web Vulnerability Scanner — S&S Security Research",
    )
    sub = parser.add_subparsers(dest="command")

    # scan
    scan_p = sub.add_parser("scan", help="Scan a target URL")
    scan_p.add_argument("url",        help="Target URL")
    scan_p.add_argument("--no-sqli",  action="store_true", help="Skip SQLi")
    scan_p.add_argument("--no-xss",   action="store_true", help="Skip XSS")
    scan_p.add_argument("--cookie",   type=str, default="",
                        help='Session cookie e.g. "PHPSESSID=abc;security=low"')

    # history
    hist_p = sub.add_parser("history", help="Show recent scans")
    hist_p.add_argument("--limit", type=int, default=10)

    # stats
    sub.add_parser("stats", help="Show statistics")

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "history":
        cmd_history(args)
    elif args.command == "stats":
        cmd_stats(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()


# python main.py scan "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie "PHPSESSID=ku2la09v7pdqg372a7naqt3gc0;security=low"