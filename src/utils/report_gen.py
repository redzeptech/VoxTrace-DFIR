from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any, Iterable

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def extract_evtx_findings_from_run_report(run_report: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Extract EVTX "critical_hits" from a VoxTrace run report JSON.

    Expected shape:
      report["modules"][...]["module"] == "evtx_scanner"
      report["modules"][...]["data"]["critical_hits"] -> list[dict]
    """
    mods = run_report.get("modules") or []
    if not isinstance(mods, list):
        return []
    for m in mods:
        if not isinstance(m, dict):
            continue
        if m.get("module") != "evtx_scanner":
            continue
        data = m.get("data") or {}
        if not isinstance(data, dict):
            continue
        hits = data.get("critical_hits") or []
        if isinstance(hits, list):
            return [h for h in hits if isinstance(h, dict)]
    return []


class PDFReporter:
    def __init__(self, output_path: str | Path):
        self.output_path = str(output_path)
        self.styles = getSampleStyleSheet()

    def generate(self, findings: Iterable[dict[str, Any]]) -> None:
        doc = SimpleDocTemplate(self.output_path, pagesize=A4)
        elements: list[Any] = []

        # Title
        elements.append(Paragraph("VoxTrace-DFIR Forensic Analysis Report", self.styles["Title"]))
        elements.append(
            Paragraph(
                f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                self.styles["Normal"],
            )
        )
        elements.append(Spacer(1, 12))

        # Table
        data = [["Timestamp", "Event ID", "Description"]]
        count = 0
        for f in findings:
            ts = str(f.get("timestamp") or "")[:19]
            eid = str(f.get("event_id") or "")
            desc = str(f.get("description") or "")
            data.append([ts, eid, desc])
            count += 1

        if count == 0:
            elements.append(Paragraph("No findings were provided.", self.styles["Normal"]))
            doc.build(elements)
            print(f"[+] Report successfully generated: {self.output_path}")
            return

        t = Table(data, colWidths=[150, 80, 250])
        t.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ]
            )
        )

        elements.append(t)
        doc.build(elements)
        print(f"[+] Report successfully generated: {self.output_path}")

    @classmethod
    def generate_from_run_report(cls, run_report_path: str | Path, output_pdf_path: str | Path) -> None:
        run_path = Path(run_report_path)
        report = json.loads(run_path.read_text(encoding="utf-8", errors="ignore"))
        findings = extract_evtx_findings_from_run_report(report)
        cls(output_pdf_path).generate(findings)

