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
    module_group.add_argument("--evtx", action="store_true", help="Analyze Windows Event Logs (event_log_collector)")
    module_group.add_argument("--mft", action="store_true", help="Analyze NTFS Master File Table (mft_parser)")

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
            chosen.add("event_log_collector")
        if bool(getattr(args, "mft", False)):
            chosen.add("mft_parser")
        if chosen and not bool(getattr(args, "all", False)):
            module_filter = chosen
        elif bool(getattr(args, "all", False)):
            module_filter = None  # run all discovered

    if module_filter:
        collectors = [c for c in collectors if c.name in module_filter]

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
    for c in collectors:
        if not c.can_run(mode):
            continue
        r = await c.run(ctx)
        results.append(asdict(r))
        if r.status == "error" and r.error:
            errors.append(f"{c.name}: {r.error}")

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
    }

    out_json.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[OK] Wrote: {out_json}")
    return 0 if not errors else 1


def main() -> None:
    import asyncio

    raise SystemExit(asyncio.run(_run(sys.argv[1:])))


if __name__ == "__main__":
    main()
