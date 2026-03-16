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

from src import __version__
from src.core.base_collector import BaseCollector, CollectorContext, CollectorMode, utc_now_iso


TOOL_NAME = "VoxTrace-DFIR"
SCHEMA_VERSION = "voxtrace.run_report.v1"


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
    ap = argparse.ArgumentParser(prog="voxtrace", description="VoxTrace-DFIR v0.3.0 (hybrid collector engine)")

    mx = ap.add_mutually_exclusive_group(required=True)
    mx.add_argument("--live", action="store_true", help="Live triage mode (collect from current host)")
    mx.add_argument("--path", default="", help="Path analysis mode (collect/parse from a folder path)")

    ap.add_argument(
        "--modules",
        default="",
        help="Comma-separated module names to run (default: all discovered)",
    )
    ap.add_argument(
        "--list-modules",
        action="store_true",
        help="List discovered modules and exit",
    )
    ap.add_argument(
        "--case",
        default="",
        help="Case identifier for the report (default: auto)",
    )
    ap.add_argument(
        "--out",
        default="",
        help="Output JSON path (default: Logs/voxtrace_run_<ts>.json)",
    )
    ap.add_argument(
        "--output-dir",
        default="",
        help="Output folder for module artifacts (default: Outputs/triage_<ts>/)",
    )
    ap.add_argument(
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

    mode: CollectorMode = "live" if bool(args.live) else "path"
    source_path = Path(args.path).resolve() if mode == "path" else None
    if mode == "path":
        if not args.path:
            print("[ERROR] --path requires a value", file=sys.stderr)
            return 2
        if not source_path or not source_path.exists():
            print(f"[ERROR] path not found: {source_path}", file=sys.stderr)
            return 2

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    case_id = (args.case or ("live" if mode == "live" else (source_path.name if source_path else "path"))).strip()
    case_id = case_id.replace(" ", "_") or "case"

    default_out_dir, default_out_json = _default_paths(ts, case_id)
    output_dir = Path(args.output_dir) if args.output_dir else default_out_dir
    out_json = Path(args.out) if args.out else default_out_json

    output_dir.mkdir(parents=True, exist_ok=True)
    out_json.parent.mkdir(parents=True, exist_ok=True)

    module_filter = {m.strip() for m in str(args.modules).split(",") if m.strip()} if args.modules else None
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

