"""
Report Generator — PDF report with SS watermark + footer.
"""

import os
from datetime import datetime
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.pdfgen import canvas
from reportlab.lib.enums import TA_CENTER, TA_LEFT

from core.config import REPORTS_DIR, LOGO_PATH

# ── Colors ────────────────────────────────────────────────────────────────────
COLOR_VULNERABLE = colors.HexColor("#e53e3e")
COLOR_MODERATE   = colors.HexColor("#dd6b20")
COLOR_SECURE     = colors.HexColor("#38a169")
COLOR_CRITICAL   = colors.HexColor("#e53e3e")
COLOR_HIGH       = colors.HexColor("#e53e3e")
COLOR_MEDIUM     = colors.HexColor("#dd6b20")
COLOR_LOW        = colors.HexColor("#d69e2e")
COLOR_INFO       = colors.HexColor("#38a169")
COLOR_TEXT       = colors.HexColor("#e2e8f0")
COLOR_SUBTEXT    = colors.HexColor("#a0aec0")
COLOR_ROW1       = colors.HexColor("#0d1117")
COLOR_ROW2       = colors.HexColor("#0f1318")
COLOR_BORDER     = colors.HexColor("#30363d")
COLOR_BG         = colors.HexColor("#0d1117")

VERDICT_COLOR = {
    "VULNERABLE": COLOR_VULNERABLE,
    "MODERATE":   COLOR_MODERATE,
    "SECURE":     COLOR_SECURE,
}

SEVERITY_COLOR = {
    "CRITICAL": COLOR_CRITICAL,
    "HIGH":     COLOR_HIGH,
    "MEDIUM":   COLOR_MEDIUM,
    "LOW":      COLOR_LOW,
    "INFO":     COLOR_INFO,
}


# ── Page Callback ─────────────────────────────────────────────────────────────

def _draw_page(canv, doc):
    canv.saveState()
    w, h = A4

    # Background
    canv.setFillColor(COLOR_BG)
    canv.rect(0, 0, w, h, fill=1, stroke=0)

    # Watermark
    if os.path.exists(LOGO_PATH):
        try:
            canv.setFillAlpha(0.35)
            canv.setBlendMode("Screen")
            canv.drawImage(
                LOGO_PATH,
                x=w / 2 - 150,
                y=h / 2 - 150,
                width=300,
                height=300,
                mask="auto",
                preserveAspectRatio=True,
            )
            canv.setBlendMode("Normal")
            canv.setFillAlpha(1)
        except Exception:
            pass

    # Footer
    canv.setFillAlpha(1)
    canv.setStrokeColor(COLOR_BORDER)
    canv.setLineWidth(0.5)
    canv.line(2 * cm, 1.8 * cm, w - 2 * cm, 1.8 * cm)
    canv.setFillColor(COLOR_SUBTEXT)
    canv.setFont("Helvetica", 8)
    canv.drawCentredString(w / 2, 1.2 * cm, "S&S  |  Web Vulnerability Scanner")
    canv.drawRightString(w - 2 * cm, 1.2 * cm, f"Page {doc.page}")
    canv.restoreState()


# ── Styles ────────────────────────────────────────────────────────────────────

def _s(name, size, bold=False, color=None, align=TA_LEFT, before=0, after=4):
    return ParagraphStyle(
        name,
        fontSize=size,
        fontName="Helvetica-Bold" if bold else "Helvetica",
        textColor=color or COLOR_TEXT,
        alignment=align,
        spaceBefore=before,
        spaceAfter=after,
    )


def _build_styles():
    return {
        "title":   _s("title",   20, bold=True, color=COLOR_TEXT,    align=TA_CENTER),
        "small":   _s("small",    8,             color=COLOR_SUBTEXT, align=TA_CENTER),
        "heading": _s("heading", 13, bold=True, color=COLOR_TEXT,    align=TA_LEFT, before=14, after=8),
        "normal":  _s("normal",   9,             color=COLOR_TEXT,    align=TA_LEFT),
        "key":     _s("key",      9, bold=True, color=COLOR_SUBTEXT, align=TA_LEFT),
        "val":     _s("val",      9,             color=COLOR_TEXT,    align=TA_LEFT),
        "verdict": _s("verdict", 28, bold=True, color=COLOR_TEXT,    align=TA_CENTER),
        "vmeta":   _s("vmeta",   10,             color=COLOR_SUBTEXT, align=TA_CENTER),
    }


# ── Table Style ───────────────────────────────────────────────────────────────

def _dark_table_style(header=True):
    base = [
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("GRID",          (0, 0), (-1, -1), 0.3, COLOR_BORDER),
        ("ROWBACKGROUNDS",(0, 0), (-1, -1), [COLOR_ROW1, COLOR_ROW2]),
        ("TEXTCOLOR",     (0, 0), (-1, -1), COLOR_TEXT),
    ]
    if header:
        base += [
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_ROW2),
            ("TEXTCOLOR",  (0, 0), (-1, 0), COLOR_SUBTEXT),
        ]
    return base


# ── Main Generator ────────────────────────────────────────────────────────────

def generate_report(result, scan_id: int) -> str:
    Path(REPORTS_DIR).mkdir(parents=True, exist_ok=True)

    ts       = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_{scan_id}_{ts}.pdf"
    path     = os.path.join(REPORTS_DIR, filename)

    doc = SimpleDocTemplate(
        path,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=3 * cm,
    )

    styles = _build_styles()
    story  = _build_story(result, ts, styles)

    doc.build(story, onFirstPage=_draw_page, onLaterPages=_draw_page)
    return path


# ── Story ─────────────────────────────────────────────────────────────────────

def _build_story(result, ts, S):
    story = []
    w     = A4[0] - 4 * cm
    vc    = VERDICT_COLOR.get(result.verdict, COLOR_SECURE)

    # ── Header ────────────────────────────────────────────────────────────────
    ht = Table(
        [[Paragraph("🔍  Web Vulnerability Scanner", S["title"])]],
        colWidths=[w],
    )
    ht.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#161b22")),
        ("TOPPADDING",    (0, 0), (-1, -1), 16),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 16),
        ("BOX",           (0, 0), (-1, -1), 1, COLOR_BORDER),
        ("TEXTCOLOR",     (0, 0), (-1, -1), COLOR_TEXT),
    ]))
    story += [
        ht,
        Spacer(1, 6),
        Paragraph(f"Generated: {ts} UTC  |  Target: {result.target}", S["small"]),
        Spacer(1, 14),
    ]

    # ── Verdict ───────────────────────────────────────────────────────────────
    vt = Table(
        [
            [Paragraph(f'<font color="#{_hex(vc)}"><b>{result.verdict}</b></font>', S["verdict"])],
            [Paragraph(
                f'Risk Score: <b>{result.total_score}/100</b>'
                f'  |  Risk Level: <b>{result.risk_level}</b>'
                f'  |  Findings: <b>{result.total_findings}</b>'
                f'  |  Scan Time: <b>{result.scan_time}s</b>',
                S["vmeta"],
            )],
        ],
        colWidths=[w],
    )
    vt.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#161b22")),
        ("BOX",           (0, 0), (-1, -1), 1.5, vc),
        ("TOPPADDING",    (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
        ("TEXTCOLOR",     (0, 0), (-1, -1), COLOR_TEXT),
    ]))
    story += [vt, Spacer(1, 20)]

    # ── Scan Summary ──────────────────────────────────────────────────────────
    story += [
        Paragraph("📊  Scan Summary", S["heading"]),
        HRFlowable(width="100%", thickness=1, color=COLOR_BORDER),
        Spacer(1, 8),
    ]
    crawl = result.crawl
    summary_rows = [
        ("Target URL",       result.target),
        ("Pages Crawled",    str(len(crawl.pages))  if crawl else "0"),
        ("Forms Found",      str(len(crawl.forms))  if crawl else "0"),
        ("URLs w/ Params",   str(len(crawl.params)) if crawl else "0"),
        ("Server",           crawl.server           if crawl else "N/A"),
        ("Tech Stack",       ", ".join(crawl.tech_stack) if crawl and crawl.tech_stack else "N/A"),
        ("SQLi Findings",    str(len(result.sqli_findings))),
        ("XSS Findings",     str(len(result.xss_findings))),
        ("Open Redirects",   str(len(result.redirect_findings))),
        ("Sensitive Files",  str(len(result.sensitive_files))),
        ("Scan Duration",    f"{result.scan_time}s"),
    ]
    st = Table(
        [[Paragraph(k, S["key"]), Paragraph(str(v)[:80], S["val"])]
         for k, v in summary_rows],
        colWidths=[4 * cm, w - 4 * cm],
    )
    st.setStyle(TableStyle(_dark_table_style(header=False)))
    story += [st, Spacer(1, 20)]

    # ── SQLi Findings ─────────────────────────────────────────────────────────
    story += [
        Paragraph(f"💉  SQL Injection  ({len(result.sqli_findings)} found)", S["heading"]),
        HRFlowable(width="100%", thickness=1, color=COLOR_BORDER),
        Spacer(1, 8),
    ]
    if not result.sqli_findings:
        story.append(Paragraph("No SQL Injection vulnerabilities detected.", S["normal"]))
    else:
        rows = [[
            Paragraph("<b>Severity</b>", S["key"]),
            Paragraph("<b>Parameter</b>", S["key"]),
            Paragraph("<b>Payload</b>", S["key"]),
            Paragraph("<b>URL</b>", S["key"]),
        ]]
        for f in result.sqli_findings:
            rows.append([
                Paragraph(f'<font color="#{_hex(COLOR_CRITICAL)}"><b>CRITICAL</b></font>', S["normal"]),
                Paragraph(f.parameter, S["normal"]),
                Paragraph(f.payload[:40], S["normal"]),
                Paragraph(f.url[:50], S["normal"]),
            ])
        t = Table(rows, colWidths=[2*cm, 2.5*cm, 4*cm, w-8.5*cm])
        t.setStyle(TableStyle(_dark_table_style(header=True)))
        story.append(t)
    story.append(Spacer(1, 20))

    # ── XSS Findings ──────────────────────────────────────────────────────────
    story += [
        Paragraph(f"⚡  Cross-Site Scripting  ({len(result.xss_findings)} found)", S["heading"]),
        HRFlowable(width="100%", thickness=1, color=COLOR_BORDER),
        Spacer(1, 8),
    ]
    if not result.xss_findings:
        story.append(Paragraph("No XSS vulnerabilities detected.", S["normal"]))
    else:
        rows = [[
            Paragraph("<b>Severity</b>", S["key"]),
            Paragraph("<b>Method</b>", S["key"]),
            Paragraph("<b>Parameter</b>", S["key"]),
            Paragraph("<b>URL</b>", S["key"]),
        ]]
        for f in result.xss_findings:
            rows.append([
                Paragraph(f'<font color="#{_hex(COLOR_HIGH)}"><b>HIGH</b></font>', S["normal"]),
                Paragraph(f.method, S["normal"]),
                Paragraph(f.parameter, S["normal"]),
                Paragraph(f.url[:55], S["normal"]),
            ])
        t = Table(rows, colWidths=[2*cm, 2*cm, 2.5*cm, w-6.5*cm])
        t.setStyle(TableStyle(_dark_table_style(header=True)))
        story.append(t)
    story.append(Spacer(1, 20))

    # ── Open Redirect ─────────────────────────────────────────────────────────
    if result.redirect_findings:
        story += [
            Paragraph(f"↪️  Open Redirect  ({len(result.redirect_findings)} found)", S["heading"]),
            HRFlowable(width="100%", thickness=1, color=COLOR_BORDER),
            Spacer(1, 8),
        ]
        rows = [[
            Paragraph("<b>Severity</b>", S["key"]),
            Paragraph("<b>Parameter</b>", S["key"]),
            Paragraph("<b>URL</b>", S["key"]),
        ]]
        for f in result.redirect_findings:
            rows.append([
                Paragraph(f'<font color="#{_hex(COLOR_MEDIUM)}"><b>MEDIUM</b></font>', S["normal"]),
                Paragraph(f.parameter, S["normal"]),
                Paragraph(f.url[:65], S["normal"]),
            ])
        t = Table(rows, colWidths=[2*cm, 2.5*cm, w-4.5*cm])
        t.setStyle(TableStyle(_dark_table_style(header=True)))
        story += [t, Spacer(1, 20)]

    # ── Sensitive Files ───────────────────────────────────────────────────────
    story += [
        Paragraph(f"📁  Sensitive Files  ({len(result.sensitive_files)} found)", S["heading"]),
        HRFlowable(width="100%", thickness=1, color=COLOR_BORDER),
        Spacer(1, 8),
    ]
    if not result.sensitive_files:
        story.append(Paragraph("No sensitive files exposed.", S["normal"]))
    else:
        rows = [[
            Paragraph("<b>Severity</b>", S["key"]),
            Paragraph("<b>Status</b>", S["key"]),
            Paragraph("<b>URL</b>", S["key"]),
        ]]
        for f in result.sensitive_files:
            sc = SEVERITY_COLOR.get(f.severity, COLOR_MEDIUM)
            rows.append([
                Paragraph(f'<font color="#{_hex(sc)}"><b>{f.severity}</b></font>', S["normal"]),
                Paragraph(str(f.status_code), S["normal"]),
                Paragraph(f.url[:65], S["normal"]),
            ])
        t = Table(rows, colWidths=[2*cm, 1.5*cm, w-3.5*cm])
        t.setStyle(TableStyle(_dark_table_style(header=True)))
        story.append(t)
    story.append(Spacer(1, 20))

    # ── Security Headers ──────────────────────────────────────────────────────
    story += [
        Paragraph("🛡️  Security Headers", S["heading"]),
        HRFlowable(width="100%", thickness=1, color=COLOR_BORDER),
        Spacer(1, 8),
    ]
    if result.headers and result.headers.findings:
        rows = [[
            Paragraph("<b>Status</b>", S["key"]),
            Paragraph("<b>Header</b>", S["key"]),
            Paragraph("<b>Severity</b>", S["key"]),
            Paragraph("<b>Detail</b>", S["key"]),
        ]]
        for f in result.headers.findings:
            status_color = COLOR_INFO if f.present else SEVERITY_COLOR.get(f.severity, COLOR_MEDIUM)
            status_text  = "PRESENT" if f.present else "MISSING"
            rows.append([
                Paragraph(f'<font color="#{_hex(status_color)}"><b>{status_text}</b></font>', S["normal"]),
                Paragraph(f.header[:30], S["normal"]),
                Paragraph(f.severity if not f.present else "INFO", S["normal"]),
                Paragraph(f.description[:60], S["normal"]),
            ])
        t = Table(rows, colWidths=[2*cm, 3.5*cm, 1.8*cm, w-7.3*cm])
        t.setStyle(TableStyle(_dark_table_style(header=True)))
        story.append(t)

        # CORS
        if result.headers.cors_misconfigured:
            story += [
                Spacer(1, 10),
                Paragraph(
                    f'<font color="#{_hex(COLOR_HIGH)}"><b>⚠ CORS Misconfiguration:</b></font> {result.headers.cors_detail}',
                    S["normal"],
                ),
            ]
    story.append(Spacer(1, 20))

    return story


# ── Helper ────────────────────────────────────────────────────────────────────

def _hex(color):
    r = int(color.red   * 255)
    g = int(color.green * 255)
    b = int(color.blue  * 255)
    return f"{r:02x}{g:02x}{b:02x}"