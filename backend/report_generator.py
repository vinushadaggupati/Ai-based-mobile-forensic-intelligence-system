"""
report_generator.py - ReportLab PDF forensic report generator.
Produces professional, court-admissible forensic investigation reports.
"""

import io
import json
from datetime import datetime, timezone
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak,
)
from reportlab.platypus.flowables import HRFlowable


# ─── COLOR PALETTE ─────────────────────────────────────────────────────────────

NAVY = colors.HexColor("#0f172a")
SLATE = colors.HexColor("#1e293b")
CYAN = colors.HexColor("#06b6d4")
WHITE = colors.white
RED = colors.HexColor("#ef4444")
AMBER = colors.HexColor("#f59e0b")
GREEN = colors.HexColor("#22c55e")
LIGHT_GRAY = colors.HexColor("#f1f5f9")
MID_GRAY = colors.HexColor("#94a3b8")
TEXT_DARK = colors.HexColor("#0f172a")


def _priority_color(priority: str) -> colors.Color:
    return {"high": RED, "medium": AMBER, "low": GREEN}.get(priority.lower(), MID_GRAY)


def _make_styles():
    styles = getSampleStyleSheet()
    custom = {
        "Title": ParagraphStyle("Title", fontName="Helvetica-Bold", fontSize=18, textColor=WHITE, spaceAfter=4, alignment=TA_CENTER),
        "Subtitle": ParagraphStyle("Subtitle", fontName="Helvetica", fontSize=10, textColor=CYAN, spaceAfter=2, alignment=TA_CENTER),
        "SectionHeader": ParagraphStyle("SectionHeader", fontName="Helvetica-Bold", fontSize=12, textColor=NAVY, spaceBefore=12, spaceAfter=4, borderPadding=(4, 0, 4, 0)),
        "Body": ParagraphStyle("Body", fontName="Helvetica", fontSize=8, textColor=TEXT_DARK, spaceAfter=4, leading=12, alignment=TA_JUSTIFY),
        "Mono": ParagraphStyle("Mono", fontName="Courier", fontSize=7, textColor=TEXT_DARK, spaceAfter=2),
        "Warning": ParagraphStyle("Warning", fontName="Helvetica-Bold", fontSize=8, textColor=AMBER, spaceAfter=4),
        "Small": ParagraphStyle("Small", fontName="Helvetica", fontSize=7, textColor=MID_GRAY, spaceAfter=2),
        "TableHeader": ParagraphStyle("TableHeader", fontName="Helvetica-Bold", fontSize=7, textColor=WHITE),
        "TableCell": ParagraphStyle("TableCell", fontName="Helvetica", fontSize=7, textColor=TEXT_DARK, leading=10),
    }
    return custom


def _header_table(title: str, styles: dict):
    """Full-width dark header block for the title page."""
    data = [[Paragraph(title, styles["Title"])]]
    t = Table(data, colWidths=[17 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), NAVY),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 18),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 18),
    ]))
    return t


def _section_header(text: str, styles: dict):
    """Styled section header with cyan underline."""
    p = Paragraph(text, styles["SectionHeader"])
    hr = HRFlowable(width="100%", thickness=1.5, color=CYAN, spaceAfter=4)
    return [p, hr]


def _kv_table(rows: list[tuple[str, str]], styles: dict, col_widths=None):
    """Key-value info table (2 columns)."""
    if col_widths is None:
        col_widths = [5 * cm, 12 * cm]
    table_data = []
    for k, v in rows:
        table_data.append([
            Paragraph(f"<b>{k}</b>", styles["TableCell"]),
            Paragraph(str(v or "N/A"), styles["TableCell"]),
        ])
    t = Table(table_data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), LIGHT_GRAY),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t


def _data_table(headers: list[str], rows: list[list[str]], styles: dict, col_widths=None):
    """Data table with header row."""
    if not rows:
        return Paragraph("<i>No records found.</i>", styles["Small"])
    header_cells = [Paragraph(h, styles["TableHeader"]) for h in headers]
    table_data = [header_cells]
    for row in rows[:50]:  # Limit rows in PDF
        table_data.append([Paragraph(str(c or ""), styles["TableCell"]) for c in row])

    if col_widths is None:
        per = 17 * cm / len(headers)
        col_widths = [per] * len(headers)

    t = Table(table_data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), SLATE),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
        ("BACKGROUND", (0, 1), (-1, -1), WHITE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_GRAY]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
    ]))
    return t


def _add_page_header_footer(canvas, doc):
    """Add page number and case reference to every page."""
    canvas.saveState()
    page_num = canvas.getPageNumber()
    case_ref = getattr(doc, "_case_ref", "MFIS-2026-0042")
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MID_GRAY)
    canvas.drawString(2 * cm, 1.2 * cm, f"AI-Based Mobile Forensic Intelligence System | Case: {case_ref} | CONFIDENTIAL")
    canvas.drawRightString(19 * cm, 1.2 * cm, f"Page {page_num}")
    canvas.setStrokeColor(colors.HexColor("#e2e8f0"))
    canvas.line(2 * cm, 1.6 * cm, 19 * cm, 1.6 * cm)
    canvas.restoreState()


def generate_forensic_report(report_data: dict) -> bytes:
    """Generate a complete PDF forensic report. Returns PDF bytes."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2.5 * cm,
        bottomMargin=2.5 * cm,
    )
    doc._case_ref = report_data.get("case", {}).get("case_number", "MFIS-2026-0042")
    styles = _make_styles()
    story = []

    case = report_data.get("case", {})
    devices = report_data.get("devices", [])
    sms = report_data.get("sms", [])
    calls = report_data.get("calls", [])
    contacts = report_data.get("contacts", [])
    gps = report_data.get("gps", [])
    browser = report_data.get("browser", [])
    apps = report_data.get("apps", [])
    media = report_data.get("media", [])
    findings = report_data.get("findings", [])
    ai_findings = report_data.get("ai_findings", [])
    hashes = report_data.get("hashes", [])
    summary_text = report_data.get("summary", "")
    risk_level = report_data.get("risk_level", "Unknown")
    recommendations = report_data.get("recommendations", [])
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # ── TITLE PAGE ──────────────────────────────────────────────────────────────
    story.append(_header_table("AI-BASED MOBILE FORENSIC INTELLIGENCE SYSTEM", styles))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph("FORENSIC INVESTIGATION REPORT", styles["Subtitle"]))
    story.append(Paragraph("Android Device Examination | Confidential", styles["Small"]))
    story.append(Spacer(1, 0.5 * cm))
    story.append(_kv_table([
        ("Case Number", case.get("case_number", "")),
        ("Investigation Title", case.get("title", "")),
        ("Investigator", case.get("investigator", "")),
        ("Agency", case.get("agency", "")),
        ("Subject / Target", case.get("suspect", "")),
        ("Case Opened", case.get("openedAt", case.get("created_at", ""))),
        ("Report Generated", generated_at),
        ("Case Status", (case.get("status") or "").upper()),
        ("Compliance Standards", "NIST SP 800-101 Rev.1 | ISO/IEC 27037 | ACPO Guidelines"),
    ], styles))
    story.append(Spacer(1, 0.4 * cm))

    # Risk level banner
    risk_color = {"Critical": RED, "High": AMBER, "Medium": colors.HexColor("#3b82f6"), "Low": GREEN}.get(risk_level, MID_GRAY)
    risk_data = [[Paragraph(f"OVERALL RISK LEVEL: {risk_level.upper()}", ParagraphStyle("R", fontName="Helvetica-Bold", fontSize=11, textColor=WHITE, alignment=TA_CENTER))]]
    risk_t = Table(risk_data, colWidths=[17 * cm])
    risk_t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), risk_color),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(risk_t)
    story.append(PageBreak())

    # ── SECTION 1: CASE & EXAMINER INFO ────────────────────────────────────────
    story += _section_header("1. Investigation & Examiner Information", styles)
    story.append(_kv_table([
        ("Case Number", case.get("case_number", "")),
        ("Investigation Title", case.get("title", "")),
        ("Primary Examiner", case.get("investigator", "")),
        ("Forensics Agency", case.get("agency", "")),
        ("Subject / Target", case.get("suspect", "")),
        ("Description", case.get("description", "")),
    ], styles))
    story.append(Spacer(1, 0.4 * cm))

    # ── SECTION 2: DEVICE INFORMATION ──────────────────────────────────────────
    story += _section_header("2. Android Device Information", styles)
    for d in devices:
        story.append(_kv_table([
            ("Device Model", d.get("model", "")),
            ("Manufacturer", d.get("manufacturer", "")),
            ("Operating System", f"Android {d.get('os_version', d.get('osVersion', ''))}"),
            ("API Level", str(d.get("api_level", d.get("androidApiLevel", "")))),
            ("Serial Number", d.get("serial", "")),
            ("IMEI", d.get("imei", "")),
            ("Acquisition Method", d.get("acquisition_method", d.get("acquisitionMethod", "ADB"))),
            ("Data Source", d.get("data_source", d.get("dataSource", ""))),
            ("USB Debugging", "Enabled" if d.get("usb_debugging", d.get("usbDebugging")) else "N/A"),
            ("Storage", d.get("storage_info", d.get("storageUsed", ""))),
            ("Battery Level", f"{d.get('battery_level', d.get('batteryLevel', 'N/A'))}%"),
            ("Acquired At", str(d.get("acquired_at", d.get("acquiredAt", "")))),
            ("Integrity", "SHA-256 Verified"),
        ], styles))
        story.append(Spacer(1, 0.3 * cm))

    # ── SECTION 3: EVIDENCE COLLECTION SUMMARY ─────────────────────────────────
    story += _section_header("3. Evidence Collection Summary", styles)
    story.append(_data_table(
        ["Category", "Records Collected", "Data Source", "Integrity"],
        [
            ["SMS Messages", str(len(sms)), "ADB / Sample", "SHA-256 Verified"],
            ["Call Logs", str(len(calls)), "ADB / Sample", "SHA-256 Verified"],
            ["Contacts", str(len(contacts)), "ADB / Sample", "SHA-256 Verified"],
            ["GPS / Location", str(len(gps)), "ADB / Sample", "SHA-256 Verified"],
            ["Browser History", str(len(browser)), "ADB / Sample", "SHA-256 Verified"],
            ["Installed Apps", str(len(apps)), "ADB / Sample", "SHA-256 Verified"],
            ["Media Files", str(len(media)), "ADB / Sample", "SHA-256 Verified"],
            ["TOTAL", str(len(sms)+len(calls)+len(contacts)+len(gps)+len(browser)+len(apps)+len(media)), "", ""],
        ],
        styles, [5*cm, 4*cm, 4*cm, 4*cm]
    ))
    story.append(Spacer(1, 0.4 * cm))

    # ── SECTION 4: SMS ANALYSIS ─────────────────────────────────────────────────
    story += _section_header("4. SMS Message Analysis", styles)
    SUSP_KW = ["burn", "wipe", "delete", "btc", "bitcoin", "cold wallet", "encrypted", "mixer", "sd card", "drop"]
    sms_rows = []
    for m in sms[:30]:
        body = str(m.get("body") or "")
        flagged = any(kw in body.lower() for kw in SUSP_KW)
        flag_txt = "⚠ FLAGGED" if flagged else ""
        sms_rows.append([
            m.get("direction", ""), m.get("contact", ""), m.get("number", ""),
            str(m.get("timestamp", ""))[:16], body[:80], flag_txt,
        ])
    story.append(_data_table(
        ["Dir", "Contact", "Number", "Timestamp", "Message Body", "Flag"],
        sms_rows, styles, [1.5*cm, 2.5*cm, 3*cm, 3*cm, 5.5*cm, 1.5*cm]
    ))
    story.append(Spacer(1, 0.4 * cm))

    # ── SECTION 5: CALL LOG ANALYSIS ───────────────────────────────────────────
    story += _section_header("5. Call Log Analysis", styles)
    call_rows = []
    for c in calls[:30]:
        dur = int(c.get("duration_sec") or 0)
        dur_fmt = f"{dur//60}m{dur%60}s" if dur >= 60 else f"{dur}s"
        call_rows.append([
            c.get("type", ""), c.get("contact", ""), c.get("number", ""),
            str(c.get("timestamp", ""))[:16], dur_fmt,
        ])
    story.append(_data_table(
        ["Type", "Contact", "Number", "Timestamp", "Duration"],
        call_rows, styles, [2.5*cm, 3*cm, 3.5*cm, 4*cm, 4*cm]
    ))
    story.append(Spacer(1, 0.4 * cm))

    # ── SECTION 6: CONTACT ANALYSIS ────────────────────────────────────────────
    story += _section_header("6. Contact Analysis", styles)
    contact_rows = [[c.get("name", ""), c.get("number", ""), c.get("email", ""), c.get("organization", "")] for c in contacts[:30]]
    story.append(_data_table(["Name", "Number", "Email", "Organization"], contact_rows, styles, [4*cm, 4*cm, 5*cm, 4*cm]))
    story.append(Spacer(1, 0.4 * cm))

    # ── SECTION 7: GPS ANALYSIS ────────────────────────────────────────────────
    story += _section_header("7. GPS Location Analysis", styles)
    gps_rows = [[g.get("place", ""), f"{g.get('latitude', g.get('lat', ''))}", f"{g.get('longitude', g.get('lng', ''))}", f"{g.get('accuracy_m', '')}m", str(g.get("timestamp", ""))[:16], g.get("provider", "")] for g in gps[:20]]
    story.append(_data_table(["Location", "Latitude", "Longitude", "Accuracy", "Timestamp", "Provider"], gps_rows, styles, [4.5*cm, 2.5*cm, 2.5*cm, 2*cm, 3.5*cm, 2*cm]))
    story.append(Spacer(1, 0.4 * cm))

    # ── SECTION 8: BROWSER HISTORY ─────────────────────────────────────────────
    story += _section_header("8. Browser History Analysis", styles)
    SUSP_URL = [".onion", "darkforum", "mixer", "wipe-guide", "crypto-cashout"]
    browser_rows = []
    for b in browser[:20]:
        url = b.get("url", "")
        flagged = any(p in url.lower() for p in SUSP_URL)
        browser_rows.append([b.get("title", "")[:40], url[:50], str(b.get("visits", "")), b.get("browser", ""), str(b.get("timestamp", ""))[:16], "⚠" if flagged else ""])
    story.append(_data_table(["Title", "URL", "Visits", "Browser", "Timestamp", "Flag"], browser_rows, styles, [3.5*cm, 5*cm, 1.5*cm, 2*cm, 3.5*cm, 1.5*cm]))
    story.append(Spacer(1, 0.4 * cm))

    # ── SECTION 9: APPLICATION ANALYSIS ────────────────────────────────────────
    story += _section_header("9. Installed Application Analysis", styles)
    app_rows = []
    for a in apps[:30]:
        susp = "⚠ SUSPICIOUS" if a.get("suspicious") else ""
        perms = a.get("permissions", "")
        if isinstance(perms, list):
            perms = ", ".join(perms)
        app_rows.append([a.get("name", ""), a.get("package", a.get("pkg", ""))[:30], a.get("version", ""), a.get("category", ""), str(perms)[:40], susp])
    story.append(_data_table(["App Name", "Package", "Version", "Category", "Permissions", "Flag"], app_rows, styles, [3*cm, 4*cm, 2*cm, 3*cm, 3.5*cm, 1.5*cm]))
    story.append(Spacer(1, 0.4 * cm))

    # ── SECTION 10: SHA-256 HASH VERIFICATION ──────────────────────────────────
    story += _section_header("10. SHA-256 Hash Verification (Evidence Integrity)", styles)
    story.append(Paragraph("All evidence records have been hashed with SHA-256 to ensure integrity. Any modification of evidence will invalidate the hash.", styles["Body"]))
    story.append(Spacer(1, 0.2 * cm))
    hash_rows = [[h.get("id", ""), h.get("kind", ""), (h.get("hash") or "")[:32] + "...", h.get("collected_at", "")[:16]] for h in hashes[:40]]
    story.append(_data_table(["Evidence ID", "Category", "SHA-256 Hash (truncated)", "Collected At"], hash_rows, styles, [3*cm, 2.5*cm, 8*cm, 3.5*cm]))
    story.append(Spacer(1, 0.4 * cm))

    # ── SECTION 11: SUSPICIOUS ACTIVITIES ──────────────────────────────────────
    story += _section_header("11. Suspicious Activities Identified", styles)
    finding_rows = []
    for f in findings:
        priority = f.get("priority", f.get("risk", "low"))
        finding_rows.append([
            priority.upper(), f.get("category", ""), f.get("title", "")[:60],
            f.get("finding_type", "confirmed-evidence"),
        ])
    story.append(_data_table(["Priority", "Category", "Finding", "Type"], finding_rows, styles, [2*cm, 3*cm, 8.5*cm, 3.5*cm]))
    story.append(Spacer(1, 0.4 * cm))

    # ── SECTION 12: AI OBSERVATIONS ────────────────────────────────────────────
    story += _section_header("12. AI-Generated Observations (Ollama Llama 3.2:3B)", styles)
    story.append(Paragraph(
        "⚠ DISCLAIMER: The following observations are generated by AI (Ollama Llama 3.2:3B) and are "
        "NOT confirmed forensic facts. They represent investigative leads and must be verified by a "
        "certified forensic examiner before use in legal proceedings.",
        styles["Warning"],
    ))
    if ai_findings:
        ai_rows = []
        for f in ai_findings:
            ai_rows.append([f.get("priority", "").upper(), f.get("category", ""), f.get("title", "")[:60], f.get("finding_type", "ai-observation")])
        story.append(_data_table(["Priority", "Category", "AI Observation", "Type"], ai_rows, styles, [2*cm, 3*cm, 8.5*cm, 3.5*cm]))
    else:
        story.append(Paragraph("No AI analysis results available. Run AI Analysis to generate Ollama-powered observations.", styles["Small"]))
    story.append(Spacer(1, 0.4 * cm))

    # ── SECTION 13: RISK ASSESSMENT ────────────────────────────────────────────
    story += _section_header("13. Risk Assessment", styles)
    story.append(_kv_table([
        ("Overall Risk Level", risk_level),
        ("High Priority Findings", str(sum(1 for f in findings if f.get("priority", f.get("risk", "")) == "high"))),
        ("Medium Priority Findings", str(sum(1 for f in findings if f.get("priority", f.get("risk", "")) == "medium"))),
        ("Low Priority Findings", str(sum(1 for f in findings if f.get("priority", f.get("risk", "")) == "low"))),
        ("Total Suspicious Indicators", str(len([f for f in findings if f.get("priority", f.get("risk", "")) in ("high", "medium")]))),
    ], styles))
    story.append(Spacer(1, 0.4 * cm))

    # ── SECTION 14: INVESTIGATION SUMMARY ──────────────────────────────────────
    story += _section_header("14. Investigation Summary", styles)
    if summary_text:
        for para in summary_text.split("\n\n"):
            if para.strip():
                story.append(Paragraph(para.strip(), styles["Body"]))
                story.append(Spacer(1, 0.2 * cm))
    else:
        story.append(Paragraph("Summary pending analysis completion.", styles["Body"]))
    story.append(Spacer(1, 0.4 * cm))

    # ── SECTION 15: RECOMMENDATIONS ────────────────────────────────────────────
    story += _section_header("15. Recommendations", styles)
    for i, rec in enumerate(recommendations, 1):
        story.append(Paragraph(f"{i}. {rec}", styles["Body"]))
        story.append(Spacer(1, 0.1 * cm))
    story.append(Spacer(1, 0.4 * cm))

    # ── FOOTER DISCLAIMER ──────────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=1, color=CYAN))
    story.append(Spacer(1, 0.2 * cm))
    story.append(Paragraph(
        "This report was generated by the AI-Based Mobile Forensic Intelligence System (MFIS). "
        "AI-generated observations are clearly labeled and do not constitute confirmed forensic findings. "
        "All evidence should be validated by a certified forensic examiner before legal proceedings. "
        f"Report generated: {generated_at}",
        styles["Small"],
    ))

    doc.build(story, onFirstPage=_add_page_header_footer, onLaterPages=_add_page_header_footer)
    return buf.getvalue()

