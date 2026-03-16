from __future__ import annotations

import argparse
import importlib
import json
import os
import pkgutil
import socket
import sys
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Proje ana dizinini (root) Python yoluna ekle
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import __version__
from src.core.base_collector import BaseCollector, CollectorContext, CollectorMode, utc_now_iso
from src.core.timeline_engine import TimelineEngine
from src.utils.report_gen import PDFReporter
from src.modules.registry_scanner import RegistryScanner
from src.modules.mft_scanner import MFTScanner


TOOL_NAME = "VoxTrace-DFIR"
SCHEMA_VERSION = "voxtrace.run_report.v1"

ASCII_BANNER = r"""
__   __            _____                      _____  ______ _____ _____
\ \ / /           |_   _|                    |  __ \|  ____|_   _|  __ \
 \ V / ___ __  __   | |_ __ __ _  ___ ___    | |  | | |__    | | | |__) |
  > < / _ \ \ \/ /   | | '__/ _` |/ __/ _ \   | |  | |  __|   | | |  _  /
 / ^ \ (_) >  <     | | | | (_| | (_|  __/   | |__| | |     _| |_| | \ \
/_/ \_\___/_/\_\    \_/_|  \__,_|\___\___|   |_____/|_|    |_____|_|  \_\
"""


def _host_info() -> dict[str, Any]:
    info: dict[str, Any] = {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "user": os.getenv("USERNAME") or os.getenv("USER") or "",
        "machine_id": hex(uuid.getnode()),
        "platform": sys.platform,
    }
    return info


def _discover_collectors() -> list[BaseCollector]:
    import src.modules  # noqa: F401

    collectors: list[BaseCollector] = []

    pkg = importlib.import_module("src.modules")
    for m in pkgutil.iter_modules(pkg.__path__):
        modname = m.name
        full = f"src.modules.{modname}"
        try:
            mod = importlib.import_module(full)
        except Exception as e:
            # module import failed; surface as stderr but continue
            print(f"[WARN] Failed to import {full}: {e}", file=sys.stderr)
            continue

        col: BaseCollector | None = None
        if hasattr(mod, "get_collector"):
            try:
                col = mod.get_collector()  # type: ignore[attr-defined]
            except Exception as e:
                print(f"[WARN] {full}.get_collector() failed: {e}", file=sys.stderr)
                continue
        elif hasattr(mod, "COLLECTOR"):
            col = getattr(mod, "COLLECTOR")

        if isinstance(col, BaseCollector):
            collectors.append(col)
            continue

        # Fallback: find subclass types and instantiate if possible
        for obj in vars(mod).values():
            if isinstance(obj, type) and issubclass(obj, BaseCollector) and obj is not BaseCollector:
                try:
                    inst = obj()
                except Exception:
                    continue
                collectors.append(inst)
                break

    # Dedup by name (last one wins)
    by_name: dict[str, BaseCollector] = {}
    for c in collectors:
        if getattr(c, "name", None):
            by_name[c.name] = c
    return sorted(by_name.values(), key=lambda c: c.name.lower())


def _parse_args(argv: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="VoxTrace-DFIR v0.3.0 - Hybrid Artifact Analyzer")

    # Argüman Grupları (Cursor-friendly)
    mode_group = ap.add_argument_group("Analysis Modes")
    mx = mode_group.add_mutually_exclusive_group(required=False)
    mx.add_argument("--live", action="store_true", help="Perform analysis on the current running system")
    mx.add_argument("--path", type=str, default="", help="Analyze artifacts from a specific directory (offline image)")

    module_group = ap.add_argument_group("Modules")
    module_group.add_argument("--all", action="store_true", help="Run all available modules (discovered plugins)")
    module_group.add_argument("--evtx", action="store_true", help="Analyze Windows Event Logs (EVTX Scanner)")
    module_group.add_argument("--mft", action="store_true", help="Deep scan Master File Table for deleted/hidden files")
    module_group.add_argument("--registry", action="store_true", help="Analyze Windows Registry (USB, Persistence, etc.)")

    advanced_group = ap.add_argument_group("Advanced")
    advanced_group.add_argument(
        "--modules",
        default="",
        help="Comma-separated module names to run (overrides shortcuts; default: all discovered)",
    )
    advanced_group.add_argument("--list-modules", action="store_true", help="List discovered modules and exit")
    advanced_group.add_argument("--case", default="", help="Case identifier for the report (default: auto)")
    advanced_group.add_argument("--out", default="", help="Output JSON path (default: Logs/voxtrace_run_<ts>.json)")
    advanced_group.add_argument(
        "--output-dir",
        default="",
        help="Output folder for module artifacts (default: Outputs/<case>_<ts>/)",
    )
    advanced_group.add_argument(
        "--param",
        action="append",
        default=[],
        help="Module param as module.key=value (repeatable). Example: --param event_log_collector.channels=Security,System",
    )

    return ap.parse_args(argv)


def _default_paths(ts: str, case_id: str) -> tuple[Path, Path]:
    out_dir = Path("Outputs") / f"{case_id}_{ts}"
    out_json = Path("Logs") / f"voxtrace_run_{case_id}_{ts}.json"
    return out_dir, out_json


async def _run(argv: list[str]) -> int:
    args = _parse_args(argv)

    collectors = _discover_collectors()
    if args.list_modules:
        for c in collectors:
            modes = []
            if c.supports_live:
                modes.append("live")
            if c.supports_path:
                modes.append("path")
            desc = getattr(c, "description", "") or ""
            print(f"{c.name} v{c.version} [{'/'.join(modes) or 'none'}] {desc}".rstrip())
        return 0

    print(ASCII_BANNER)
    print(f"{'=' * 70}\n[+] VoxTrace-DFIR v{__version__} initialized.\n{'=' * 70}")

    if not args.live and not args.path:
        ap = argparse.ArgumentParser(add_help=False)
        # Show the original parser help (best effort)
        print("[ERROR] You must specify one analysis mode: --live or --path\n", file=sys.stderr)
        _parse_args(["--help"])
        return 2

    mode: CollectorMode = "live" if bool(args.live) else "path"
    if mode == "live":
        print("[!] Mode: LIVE TRIAGE. (May require Admin Privileges)")
    source_path = Path(args.path).resolve() if mode == "path" else None
    if mode == "path":
        if not args.path:
            print("[ERROR] --path requires a value", file=sys.stderr)
            return 2
        if not source_path or not source_path.exists():
            print(f"[-] Error: Path '{source_path}' does not exist.", file=sys.stderr)
            return 2
        print(f"[!] Mode: OFFLINE ANALYSIS. Path: {source_path}")

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    case_id = (args.case or ("live" if mode == "live" else (source_path.name if source_path else "path"))).strip()
    case_id = case_id.replace(" ", "_") or "case"

    default_out_dir, default_out_json = _default_paths(ts, case_id)
    output_dir = Path(args.output_dir) if args.output_dir else default_out_dir
    out_json = Path(args.out) if args.out else default_out_json

    output_dir.mkdir(parents=True, exist_ok=True)
    out_json.parent.mkdir(parents=True, exist_ok=True)

    # Module selection: shortcuts first, then explicit --modules (overrides).
    module_filter: set[str] | None = None
    if args.modules:
        module_filter = {m.strip() for m in str(args.modules).split(",") if m.strip()}
    else:
        chosen: set[str] = set()
        if bool(getattr(args, "evtx", False)):
            chosen.add("evtx_scanner")
        if bool(getattr(args, "mft", False)):
            chosen.add("mft_scanner")
        if bool(getattr(args, "registry", False)):
            chosen.add("registry_scanner")
        if chosen and not bool(getattr(args, "all", False)):
            module_filter = chosen
        elif bool(getattr(args, "all", False)):
            module_filter = None  # run all discovered

    if module_filter:
        collectors = [c for c in collectors if c.name in module_filter]

    if bool(getattr(args, "evtx", False)) or bool(getattr(args, "all", False)):
        print("[>] Running EVTX Parser...")
    if bool(getattr(args, "registry", False)) or bool(getattr(args, "all", False)):
        print("[>] Running Registry Scanner...")
    if bool(getattr(args, "mft", False)) or bool(getattr(args, "all", False)):
        print("[>] Running MFT Deep Dive...")

    params: dict[str, dict[str, str]] = {}
    for raw in args.param or []:
        s = str(raw).strip()
        if not s:
            continue
        if "=" not in s or "." not in s.split("=", 1)[0]:
            print(f"[WARN] Ignoring invalid --param (expected module.key=value): {s}", file=sys.stderr)
            continue
        left, value = s.split("=", 1)
        module, key = left.split(".", 1)
        module = module.strip()
        key = key.strip()
        if not module or not key:
            print(f"[WARN] Ignoring invalid --param (empty module/key): {s}", file=sys.stderr)
            continue
        params.setdefault(module, {})[key] = value

    ctx = CollectorContext(
        tool=TOOL_NAME,
        tool_version=__version__,
        run_id=f"{case_id}_{ts}",
        case_id=case_id,
        mode=mode,
        output_dir=output_dir,
        source_path=source_path,
        params=params,
    )

    started_at = utc_now_iso()
    results = []
    errors: list[str] = []
    evtx_scanner_result: dict[str, Any] | None = None
    registry_scanner_result: dict[str, Any] | None = None
    mft_scanner_result: list[Any] | None = None
    audio_forensics_result: dict[str, Any] | None = None
    for c in collectors:
        if not c.can_run(mode):
            continue
        r = await c.run(ctx)
        results.append(asdict(r))
        if r.status == "error" and r.error:
            errors.append(f"{c.name}: {r.error}")
        if r.module == "evtx_scanner" and r.status == "ok":
            evtx_scanner_result = r.data
        if r.module == "registry_scanner" and r.status == "ok":
            registry_scanner_result = r.data
        if r.module == "mft_scanner" and r.status == "ok":
            # mft_scanner returns a list (meta + deleted hits)
            mft_scanner_result = r.data  # type: ignore[assignment]
        if r.module == "audio_forensics" and r.status == "ok":
            audio_forensics_result = r.data

    # TimelineEngine integration (aggregate module outputs)
    timeline = TimelineEngine()
    if evtx_scanner_result and isinstance(evtx_scanner_result, dict):
        evtx_results = evtx_scanner_result.get("critical_hits") or []
        if isinstance(evtx_results, list):
            timeline.add_events([e for e in evtx_results if isinstance(e, dict)], "Windows Event Log")

    if registry_scanner_result and isinstance(registry_scanner_result, dict):
        reg_results = registry_scanner_result.get("usb_devices") or []
        if isinstance(reg_results, list):
            timeline.add_events([e for e in reg_results if isinstance(e, dict)], "Registry/USB")

    if audio_forensics_result and isinstance(audio_forensics_result, dict):
        audio_results = audio_forensics_result.get("segments") or []
        if isinstance(audio_results, list):
            timeline.add_events([e for e in audio_results if isinstance(e, dict)], "Audio Evidence")

    if mft_scanner_result and isinstance(mft_scanner_result, list):
        timeline.add_events([e for e in mft_scanner_result if isinstance(e, dict)], "MFT/Deleted")

    final_timeline = timeline.generate_sorted_timeline()
    timeline_path = output_dir / "timeline_master.json"
    if final_timeline:
        timeline_path.write_text(json.dumps(final_timeline, ensure_ascii=False, indent=2), encoding="utf-8")

    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "run": {
            "run_id": ctx.run_id,
            "case_id": ctx.case_id,
            "mode": ctx.mode,
            "source_path": str(ctx.source_path) if ctx.source_path else None,
            "started_at": started_at,
            "ended_at": utc_now_iso(),
        },
        "host": _host_info(),
        "output_dir": str(output_dir),
        "modules": results,
        "errors": errors,
        "timeline": {
            "events_count": len(final_timeline),
            "path": (str(timeline_path) if final_timeline else None),
        },
    }

    out_json.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[OK] Wrote: {out_json}")

    # Pretty EVTX output + optional PDF report generation
    if evtx_scanner_result and isinstance(evtx_scanner_result, dict):
        try:
            total = int(evtx_scanner_result.get("total_logs_found") or 0)
        except Exception:
            total = 0
        files = evtx_scanner_result.get("files") or []
        if isinstance(files, list):
            files_str = ", ".join(str(x) for x in files if x)
        else:
            files_str = ""
        print(f"[+] Found {total} EVTX files.")
        if files_str:
            print(f"[+] Sample logs: {files_str}")

        show_findings = bool(getattr(args, "evtx", False)) and not bool(getattr(args, "all", False))
        hits = evtx_scanner_result.get("critical_hits") or []
        if show_findings:
            errs = evtx_scanner_result.get("errors") or []
            if errs:
                print("\n[!] EVTX WARNINGS:")
                print("-" * 50)
                if isinstance(errs, list):
                    for e in errs:
                        print(f"- {e}")
                else:
                    print(f"- {errs}")

            if isinstance(hits, list) and hits:
                print(f"\n[!] FINDINGS ({len(hits)} Critical Events):")
                print("-" * 50)
                for event in hits:
                    if not isinstance(event, dict):
                        continue
                    ts = event.get("timestamp") or "N/A"
                    eid = event.get("event_id") or "N/A"
                    desc = event.get("description") or ""
                    print(f"[{str(ts)[:19]}] ID: {eid} - {desc}")
            else:
                print("\n[!] FINDINGS (0 Critical Events):")
                print("-" * 50)
                print("No critical events captured (try running as Administrator for Security.evtx).")

        # Auto PDF report generation (after analysis)
        if bool(getattr(args, "evtx", False)) or bool(getattr(args, "all", False)):
            if isinstance(hits, list) and hits:
                Path("Outputs").mkdir(parents=True, exist_ok=True)
                report_name = f"VoxTrace_Report_{datetime.now().strftime('%H%M%S')}.pdf"
                reporter = PDFReporter(Path("Outputs") / report_name)
                reporter.generate(hits)

    # Registry console summary (USBSTOR)
    show_registry = bool(getattr(args, "registry", False)) and not bool(getattr(args, "all", False))
    if registry_scanner_result and isinstance(registry_scanner_result, dict) and show_registry:
        usb_devices = registry_scanner_result.get("usb_devices") or []
        if isinstance(usb_devices, list):
            for item in usb_devices:
                if isinstance(item, dict) and "id" in item:
                    print(f"[+] USB Device Detected: {item['id']}")

    # MFT console summary (deleted records)
    show_mft = bool(getattr(args, "mft", False)) and not bool(getattr(args, "all", False))
    if show_mft and isinstance(mft_scanner_result, list):
        for item in mft_scanner_result:
            if isinstance(item, dict) and "status" in item:
                print(f"[!] {item['status']} File Found: {item.get('filename')} (Created: {item.get('created')})")

    return 0 if not errors else 1


def main() -> None:
    import asyncio

    raise SystemExit(asyncio.run(_run(sys.argv[1:])))


if __name__ == "__main__":
    main()
