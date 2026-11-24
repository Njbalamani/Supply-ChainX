from __future__ import annotations

import csv
import hashlib
import io
import json
from pathlib import Path

from django.core.files.base import ContentFile

from config.constants import Severity


def _file_checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def vulnerability_csv_bytes(scan) -> bytes:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "scan_id", "project", "package", "version", "ecosystem", "is_direct", "advisory_id",
            "cve_id", "severity", "cvss_score", "source", "source_url", "fixed_versions",
            "summary", "references",
        ]
    )
    for vuln in scan.vulnerabilities.all():
        writer.writerow(
            [
                scan.pk,
                scan.project.name,
                vuln.package_name,
                vuln.package_version,
                vuln.ecosystem,
                vuln.is_direct,
                vuln.vuln_id,
                vuln.cve_id,
                vuln.severity,
                vuln.cvss_score if vuln.cvss_score is not None else "",
                "+".join(vuln.sources) if vuln.sources else vuln.source,
                vuln.source_url,
                ";".join(vuln.fixed_versions),
                vuln.summary.replace("\n", " ")[:500],
                ";".join(vuln.references[:5]),
            ]
        )
    return output.getvalue().encode("utf-8-sig")


def risk_summary_dict(scan) -> dict:
    metrics = getattr(scan, "graph_metrics", None)
    license_report = getattr(scan, "license_report", None)
    vuln_counts = {key: 0 for key in [s[0] for s in Severity.choices]}
    for vuln in scan.vulnerabilities.all():
        vuln_counts[vuln.severity] = vuln_counts.get(vuln.severity, 0) + 1
    return {
        "scan_id": scan.pk,
        "project": scan.project.name,
        "organization": scan.project.organization.name,
        "status": scan.status,
        "risk_score": scan.risk_score,
        "health_score": scan.health_score,
        "dependency_count": scan.dependencies.count(),
        "vulnerability_count": scan.vulnerabilities.count(),
        "vulnerabilities_by_severity": vuln_counts,
        "graph": {
            "nodes": metrics.node_count if metrics else 0,
            "edges": metrics.edge_count if metrics else 0,
            "vulnerable_nodes": metrics.vulnerable_node_count if metrics else 0,
            "max_depth": metrics.max_depth if metrics else 0,
            "vulnerable_paths": metrics.vulnerable_paths[:10] if metrics else [],
        },
        "license": license_report.summary if license_report else {},
        "database_sources": scan.sources,
        "scan_summary": scan.summary,
    }


def pdf_bytes(scan) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"SupplyChainX Security Report - Scan #{scan.pk}",
        author="SupplyChainX",
    )
    styles = getSampleStyleSheet()
    gold = colors.HexColor("#C9A227")
    ink = colors.HexColor("#101217")
    muted = colors.HexColor("#5D6470")
    title_style = ParagraphStyle("SCXTitle", parent=styles["Title"], fontSize=22, textColor=ink, spaceAfter=6)
    heading_style = ParagraphStyle("SCXHeading", parent=styles["Heading2"], fontSize=13, textColor=gold, spaceBefore=12)
    body_style = ParagraphStyle("SCXBody", parent=styles["BodyText"], fontSize=9, leading=13)
    small_style = ParagraphStyle("SCXSmall", parent=styles["BodyText"], fontSize=7.5, leading=10)

    summary = risk_summary_dict(scan)
    story = [
        Paragraph("SUPPLYCHAINX", title_style),
        Paragraph("Software Supply Chain Security Assessment", styles["Heading3"]),
        Spacer(1, 4 * mm),
    ]
    meta = [
        ["Project", summary["project"]],
        ["Organization", summary["organization"]],
        ["Scan ID", str(scan.pk)],
        ["Status", scan.status],
        ["Risk score", f"{scan.risk_score}/100"],
        ["Health score", f"{scan.health_score}/100"],
        ["Vulnerability sources", ", ".join(scan.sources.get("databases", [])) or "None reported"],
    ]
    table = Table(meta, colWidths=[45 * mm, 120 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F3F1EA")),
                ("TEXTCOLOR", (0, 0), (0, -1), gold),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D8D8D8")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.extend([table, Spacer(1, 6 * mm)])

    story.append(Paragraph("Executive Summary", heading_style))
    story.append(
        Paragraph(
            f"This assessment analysed <b>{summary['dependency_count']}</b> dependencies and found "
            f"<b>{summary['vulnerability_count']}</b> advisory matches across "
            f"{len(summary['vulnerabilities_by_severity'])} severity levels. Findings below are sourced from "
            "live vulnerability intelligence queries recorded on the scan; no synthetic CVE data is included.",
            body_style,
        )
    )
    story.append(Spacer(1, 3 * mm))
    severity_rows = [["Severity", "Count"]] + [
        [level, str(count)] for level, count in summary["vulnerabilities_by_severity"].items()
    ]
    sev_table = Table(severity_rows, colWidths=[80 * mm, 40 * mm])
    sev_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1B1E26")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CCCCCC")),
            ]
        )
    )
    story.extend([sev_table, Spacer(1, 4 * mm)])

    story.append(Paragraph("Vulnerability Findings", heading_style))
    vuln_rows = [["Advisory", "Package", "Severity", "CVSS", "Source"]]
    for vuln in scan.vulnerabilities.all()[:60]:
        vuln_rows.append(
            [
                Paragraph(vuln.cve_or_id, small_style),
                Paragraph(f"{vuln.package_name} {vuln.package_version}", small_style),
                vuln.severity,
                str(vuln.cvss_score) if vuln.cvss_score is not None else "-",
                "+".join(vuln.sources) if vuln.sources else vuln.source,
            ]
        )
    vuln_table = Table(vuln_rows, colWidths=[38 * mm, 55 * mm, 25 * mm, 18 * mm, 29 * mm], repeatRows=1)
    vuln_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1B1E26")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("GRID", (0, 0), (-1, -1), 0.2, colors.HexColor("#DDDDDD")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(vuln_table)

    story.append(PageBreak())
    story.append(Paragraph("Prioritized Recommendations", heading_style))
    for rec in scan.recommendations.all()[:25]:
        story.append(Paragraph(f"<b>{rec.title}</b> [{rec.priority}]", body_style))
        story.append(Paragraph(rec.explanation[:600], small_style))
        if rec.risks:
            story.append(Paragraph(f"<i>Risk:</i> {rec.risks[:300]}", small_style))
        story.append(Spacer(1, 2 * mm))

    story.append(Paragraph("Dependency Graph Summary", heading_style))
    graph = summary["graph"]
    story.append(
        Paragraph(
            f"Nodes: {graph['nodes']} | Edges: {graph['edges']} | Vulnerable nodes: "
            f"{graph['vulnerable_nodes']} | Maximum transitive depth: {graph['max_depth']}",
            body_style,
        )
    )
    story.append(Paragraph("License Compliance", heading_style))
    story.append(Paragraph(json.dumps(summary["license"], indent=2)[:1500], small_style))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("Data Sources & Disclaimer", heading_style))
    story.append(
        Paragraph(
            "Advisory matches are retrieved from OSV.dev and, where available, enriched from NVD CVE records. "
            "Optional local tools (pip-audit, gitleaks) are recorded separately when enabled. Recommendations "
            "are decision support and must be validated by a qualified engineer before deployment.",
            small_style,
        )
    )
    doc.build(story)
    return buffer.getvalue()


def create_report(scan, report_type: str, user=None, content: bytes | None = None, filename: str | None = None, title: str = ""):
    from .models import Report

    if content is None:
        if report_type == Report.ReportType.PDF:
            content = pdf_bytes(scan)
            filename = f"supplychainx-scan-{scan.pk}.pdf"
        elif report_type == Report.ReportType.VULNERABILITY_CSV:
            content = vulnerability_csv_bytes(scan)
            filename = f"supplychainx-vulnerabilities-{scan.pk}.csv"
        elif report_type == Report.ReportType.RISK_SUMMARY:
            content = json.dumps(risk_summary_dict(scan), indent=2, default=str).encode("utf-8")
            filename = f"supplychainx-risk-{scan.pk}.json"
        else:
            raise ValueError(f"Unsupported generated report type: {report_type}")
    report = Report(
        scan=scan,
        report_type=report_type,
        title=title or f"SupplyChainX {report_type} for scan #{scan.pk}",
        generated_by=user,
        checksum=_file_checksum(content),
    )
    report.file.save(filename or f"report-{scan.pk}.bin", ContentFile(content), save=True)
    return report
