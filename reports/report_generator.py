from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from datetime import datetime


def generate_report(results, findings, risk, filename="reports/security_report.pdf"):

    doc = SimpleDocTemplate(
        filename,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "Title",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=24,
        spaceAfter=10
    )

    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        alignment=TA_CENTER,
        fontSize=10,
        textColor=colors.grey,
        spaceAfter=20
    )

    heading_style = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontSize=16,
        spaceBefore=15,
        spaceAfter=10
    )

    story = []

    # TITLE
    story.append(
        Paragraph("CyberSentinel", title_style)
    )

    story.append(
        Paragraph(
            "Network Security Assessment Report",
            subtitle_style
        )
    )

    story.append(
        Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            subtitle_style
        )
    )

    # SUMMARY
    story.append(
        Paragraph("Security Summary", heading_style)
    )

    open_ports = len([
        r for r in results
        if r["state"] == "open"
    ])

    filtered_ports = len([
        r for r in results
        if r["state"] == "filtered"
    ])

    summary_data = [
        ["Metric", "Value"],
        ["Total Results", str(len(results))],
        ["Open Ports", str(open_ports)],
        ["Filtered Ports", str(filtered_ports)],
        ["Vulnerability Findings", str(len(findings))],
        ["Security Risk", risk]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[250, 180]
    )

    summary_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 8),
        ])
    )

    story.append(summary_table)

    # VULNERABILITIES
    story.append(
        Paragraph("Vulnerability Findings", heading_style)
    )

    if findings:

        vulnerability_data = [
            ["Port", "Service", "Severity", "Finding"]
        ]

        for finding in findings:

            vulnerability_data.append([
                str(finding["port"]),
                finding["service"],
                finding["severity"],
                finding["title"]
            ])

        vulnerability_table = Table(
            vulnerability_data,
            colWidths=[50, 90, 70, 220]
        )

        vulnerability_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("PADDING", (0, 0), (-1, -1), 6),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ])
        )

        story.append(vulnerability_table)

        story.append(Spacer(1, 15))

        for finding in findings:

            story.append(
                Paragraph(
                    f"<b>Recommendation:</b> "
                    f"{finding['recommendation']}",
                    styles["Normal"]
                )
            )

            story.append(Spacer(1, 8))

    else:

        story.append(
            Paragraph(
                "No potentially risky services were detected.",
                styles["Normal"]
            )
        )

    # NETWORK RESULTS
    story.append(
        Paragraph("Network Scan Results", heading_style)
    )

    if results:

        network_data = [
            ["Port", "Protocol", "State", "Service", "Product"]
        ]

        for result in results:

            network_data.append([
                str(result["port"]),
                result["protocol"],
                result["state"],
                result["service"],
                result["product"] or "-"
            ])

        network_table = Table(
            network_data,
            colWidths=[45, 60, 65, 90, 170]
        )

        network_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("PADDING", (0, 0), (-1, -1), 6),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ])
        )

        story.append(network_table)

    # FOOTER
    story.append(Spacer(1, 25))

    story.append(
        Paragraph(
            "CyberSentinel • Authorized Security Testing Platform",
            subtitle_style
        )
    )

    doc.build(story)


if __name__ == "__main__":

    print("[+] CyberSentinel PDF report generator ready.")