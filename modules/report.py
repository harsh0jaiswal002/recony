"""
report.py
---------
Renders compiled findings into a clean PDF: title/scope page, executive
summary table, then one detailed section per finding (description,
evidence, attack class, remediation).
"""

from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (PageBreak, Paragraph, SimpleDocTemplate,
                                 Spacer, Table, TableStyle)


def _esc(value):
    return escape(str(value)) if value is not None else ""


def generate_pdf(findings, metadata, output_path):
    doc = SimpleDocTemplate(
        output_path, pagesize=letter,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="FindingTitle", fontSize=12, leading=15, spaceBefore=12, spaceAfter=4,
        textColor=colors.white, backColor=colors.HexColor("#2c3e50"), leftIndent=4,
    ))

    story = []

    # --- Title / scope page -------------------------------------------------
    story.append(Spacer(1, 1.2 * inch))
    story.append(Paragraph("Web Application Reconnaissance Report", styles["Title"]))
    story.append(Spacer(1, 0.25 * inch))
    story.append(Paragraph(f"<b>Target:</b> {_esc(metadata.get('url'))}", styles["Normal"]))
    story.append(Paragraph(
        f"<b>Date:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]
    ))
    if metadata.get("tester"):
        story.append(Paragraph(f"<b>Tester:</b> {_esc(metadata.get('tester'))}", styles["Normal"]))
    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph(
        "This report was generated for an authorized security assessment. It contains passive, "
        "observational reconnaissance findings only — this tool performed no exploitation, injection, "
        "or brute-forcing against the target. Each finding's \"attack class\" describes the general "
        "category of risk a weakness contributes to, not a verified exploit. Findings should be "
        "independently verified and responsibly disclosed to the target organization's security contact.",
        styles["Normal"],
    ))
    story.append(PageBreak())

    # --- Executive summary ---------------------------------------------------
    story.append(Paragraph("Executive Summary", styles["Heading1"]))
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    table_data = [["Severity", "Count"]] + [[sev, str(counts.get(sev, 0))] for sev in order]
    t = Table(table_data, colWidths=[2 * inch, 1 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.3 * inch))

    # --- Detailed findings ---------------------------------------------------
    story.append(Paragraph("Detailed Findings", styles["Heading1"]))
    if not findings:
        story.append(Paragraph("No findings were flagged by the checks in this tool.", styles["Normal"]))

    for f in findings:
        story.append(Paragraph(f"[{_esc(f.severity)}] {_esc(f.title)}", styles["FindingTitle"]))
        story.append(Paragraph(f"<b>Description:</b> {_esc(f.description)}", styles["Normal"]))
        story.append(Paragraph(f"<b>Evidence:</b> {_esc(f.evidence)}", styles["Normal"]))
        story.append(Paragraph(_esc(f.attack_category), styles["Normal"]))
        story.append(Paragraph(f"<b>Remediation:</b> {_esc(f.remediation)}", styles["Normal"]))
        story.append(Spacer(1, 0.12 * inch))

    doc.build(story)
