import argparse
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def _safe_read_text(path: Path, max_chars: int = 20000) -> str:
    try:
        txt = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""
    if len(txt) > max_chars:
        return txt[: max_chars - 200] + "\n\n...[truncated]...\n"
    return txt


def _try_load_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None


@dataclass(frozen=True)
class FindingRow:
    indicator: str
    kind: str
    malicious: int | None
    suspicious: int | None
    harmless: int | None
    undetected: int | None
    timeout: int | None
    error: str | None
    sources: list[str]


def _parse_threat_intel_json(payload: dict[str, Any]) -> tuple[dict[str, Any], list[FindingRow]]:
    meta = {
        "scanned_path": payload.get("scanned_path"),
        "public_ips_only": payload.get("public_ips_only"),
        "include_exts": payload.get("include_exts"),
        "indicators": payload.get("indicators") or {},
    }
    sources_map: dict[str, list[str]] = payload.get("sources") or {}
    rows: list[FindingRow] = []
    for r in payload.get("results") or []:
        ind = str(r.get("indicator") or "")
        if not ind:
            continue
        rows.append(
            FindingRow(
                indicator=ind,
                kind=str(r.get("kind") or ""),
                malicious=r.get("malicious"),
                suspicious=r.get("suspicious"),
                harmless=r.get("harmless"),
                undetected=r.get("undetected"),
                timeout=r.get("timeout"),
                error=r.get("error"),
                sources=sources_map.get(ind) or [],
            )
        )
    return meta, rows


def _count_severity(rows: list[FindingRow]) -> dict[str, int]:
    out = {"malicious": 0, "suspicious": 0, "clean_or_undetected": 0, "errors": 0}
    for r in rows:
        if r.error:
            out["errors"] += 1
            continue
        mal = int(r.malicious or 0)
        sus = int(r.suspicious or 0)
        if mal > 0:
            out["malicious"] += 1
        elif sus > 0:
            out["suspicious"] += 1
        else:
            out["clean_or_undetected"] += 1
    return out


def _shorten(s: str, n: int) -> str:
    s = re.sub(r"\s+", " ", s).strip()
    if len(s) <= n:
        return s
    return s[: n - 1] + "…"


def _mask_path(s: str) -> str:
    """C:\\Users\\KullaniciAdi -> C:\\Users\\[USER]"""
    if not s:
        return s
    return re.sub(r"(?i)([A-Z]:\\Users\\)[^\\/]+", r"\1[USER]", str(s))


def _build_pdf(
    *,
    out_pdf: Path,
    case_name: str,
    output_dir: Path,
    run_log: Path | None,
    threat_intel_json: Path | None,
    include_excerpts: bool,
    max_excerpt_chars: int,
) -> None:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except Exception as e:
        raise RuntimeError(
            "Missing dependency: reportlab. Install with: pip install reportlab"
        ) from e

    out_pdf.parent.mkdir(parents=True, exist_ok=True)

    styles = getSampleStyleSheet()
    title = styles["Title"]
    h2 = styles["Heading2"]
    body = styles["BodyText"]
    mono = ParagraphStyle(
        "mono",
        parent=styles["BodyText"],
        fontName="Courier",
        fontSize=9,
        leading=11,
    )

    def on_page(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 9)
        canvas.setFillGray(0.4)
        canvas.drawString(15 * mm, 10 * mm, f"VoxTrace-DFIR Report — {case_name}")
        canvas.drawRightString(200 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        str(out_pdf),
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="VoxTrace-DFIR Report",
        author="VoxTrace-DFIR",
    )

    story: list[Any] = []
    story.append(Paragraph("VoxTrace-DFIR — Analysis Report", title))
    story.append(Spacer(1, 10))
    story.append(Paragraph(f"<b>Case</b>: {case_name}", body))
    story.append(Paragraph(f"<b>Generated</b>: {time.strftime('%Y-%m-%d %H:%M:%S')}", body))
    story.append(Paragraph(f"<b>Output directory</b>: {_mask_path(str(output_dir))}", body))
    if run_log:
        story.append(Paragraph(f"<b>Run log</b>: {_mask_path(str(run_log))}", body))
    if threat_intel_json:
        story.append(Paragraph(f"<b>Threat Intel</b>: {_mask_path(str(threat_intel_json))}", body))
    story.append(Spacer(1, 12))

    # --- Artifacts
    story.append(Paragraph("Artifacts", h2))
    artifact_files = sorted(
        [p for p in output_dir.glob("*") if p.is_file() and p.suffix.lower() in {".txt", ".srt", ".vtt", ".json", ".tsv"}],
        key=lambda p: p.name.lower(),
    )
    if artifact_files:
        data = [["File", "Size (KB)"]]
        for p in artifact_files[:200]:
            size_kb = int((p.stat().st_size + 1023) / 1024)
            data.append([p.name, str(size_kb)])
        t = Table(data, colWidths=[120 * mm, 30 * mm])
        t.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.HexColor("#f8fafc")]),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(t)
    else:
        story.append(Paragraph("No artifacts found in output directory.", body))

    # --- Threat Intel
    story.append(Spacer(1, 14))
    story.append(Paragraph("Threat Intel (VirusTotal)", h2))
    ti_rows: list[FindingRow] = []
    ti_meta: dict[str, Any] = {}
    if threat_intel_json and threat_intel_json.exists():
        payload = _try_load_json(threat_intel_json)
        if payload:
            ti_meta, ti_rows = _parse_threat_intel_json(payload)
    if not ti_rows:
        story.append(Paragraph("No Threat Intel results available (missing or empty).", body))
    else:
        sev = _count_severity(ti_rows)
        story.append(
            Paragraph(
                f"<b>Summary</b>: malicious={sev['malicious']}, suspicious={sev['suspicious']}, "
                f"clean/undetected={sev['clean_or_undetected']}, errors={sev['errors']}",
                body,
            )
        )
    if ti_meta:
        story.append(
            Paragraph(
                f"<b>Public IP only</b>: {ti_meta.get('public_ips_only')} — "
                f"<b>Scanned path</b>: {_shorten(_mask_path(str(ti_meta.get('scanned_path') or '')), 120)}",
                body,
            )
        )

        # Show top findings first
        def score_key(r: FindingRow) -> tuple[int, int, int]:
            return (int(r.malicious or 0), int(r.suspicious or 0), 1 if r.error else 0)

        ordered = sorted(ti_rows, key=score_key, reverse=True)
        data = [["Indicator", "Kind", "Mal", "Sus", "Undet", "Error", "Sources"]]
        for r in ordered[:250]:
            src = ""
            if r.sources:
                src = f"{len(r.sources)} file(s)"
                if len(r.sources) <= 2:
                    src += " — " + "; ".join(Path(_mask_path(s)).name for s in r.sources)
            data.append(
                [
                    _shorten(r.indicator, 48),
                    r.kind,
                    str(r.malicious or 0),
                    str(r.suspicious or 0),
                    str(r.undetected or 0),
                    _shorten(r.error or "", 60),
                    _shorten(src, 50),
                ]
            )
        t = Table(data, repeatRows=1, colWidths=[55 * mm, 16 * mm, 10 * mm, 10 * mm, 12 * mm, 50 * mm, 32 * mm])
        t.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.HexColor("#f8fafc")]),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(Spacer(1, 8))
        story.append(t)

    # --- Excerpts
    if include_excerpts:
        story.append(PageBreak())
        story.append(Paragraph("Text Excerpts (preview)", h2))
        story.append(
            Paragraph(
                "This section includes short previews from transcripts/subtitles for quick review. "
                "Full content remains in the output directory.",
                body,
            )
        )
        candidates = []
        for ext in (".tr.txt", ".txt", ".tr.srt", ".srt"):
            candidates.extend(sorted(output_dir.glob(f"*{ext}"), key=lambda p: p.name.lower()))
        used = 0
        for p in candidates:
            if used >= 6:
                break
            txt = _safe_read_text(p, max_chars=max_excerpt_chars)
            if not txt.strip():
                continue
            story.append(Spacer(1, 10))
            story.append(Paragraph(f"<b>{p.name}</b>", body))
            story.append(Spacer(1, 4))
            story.append(Paragraph(_shorten(txt, max_excerpt_chars).replace("\n", "<br/>"), mono))
            used += 1

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)


def main() -> None:
    ap = argparse.ArgumentParser(description="VoxTrace-DFIR Reporting Engine (PDF)")
    ap.add_argument("output_dir", help="Per-file output directory under Outputs/<file>/ (or any folder)")
    ap.add_argument("--case", default="", help="Case name (default: output folder name)")
    ap.add_argument("--run-log", default="", help="Optional run log path (Logs/run_*.log)")
    ap.add_argument("--threat-intel-json", default="", help="Optional Threat Intel JSON path (Logs/threat_intel_*.json)")
    ap.add_argument("--out", default="", help="Output PDF path (default: Logs/report_<case>_<ts>.pdf)")
    ap.add_argument("--no-excerpts", action="store_true", help="Do not include transcript excerpts")
    ap.add_argument("--excerpt-chars", type=int, default=1800, help="Max chars per excerpt (default: 1800)")
    args = ap.parse_args()

    out_dir = Path(args.output_dir)
    if not out_dir.exists() or not out_dir.is_dir():
        raise SystemExit(f"[ERROR] output_dir not found or not a directory: {out_dir}")

    case_name = args.case.strip() or out_dir.name
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_pdf = Path(args.out) if args.out else (Path("Logs") / f"report_{case_name}_{ts}.pdf")

    run_log = Path(args.run_log) if args.run_log else None
    if run_log and not run_log.exists():
        run_log = None

    ti_json = Path(args.threat_intel_json) if args.threat_intel_json else None
    if ti_json and not ti_json.exists():
        ti_json = None

    try:
        _build_pdf(
            out_pdf=out_pdf,
            case_name=case_name,
            output_dir=out_dir,
            run_log=run_log,
            threat_intel_json=ti_json,
            include_excerpts=not bool(args.no_excerpts),
            max_excerpt_chars=max(200, int(args.excerpt_chars)),
        )
    except RuntimeError as e:
        print(f"[ERROR] {e}")
        raise SystemExit(1)

    print(f"[OK] Wrote: {out_pdf}")


if __name__ == "__main__":
    main()

