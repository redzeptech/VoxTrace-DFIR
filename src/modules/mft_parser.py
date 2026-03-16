from __future__ import annotations

import asyncio
import csv
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from src.core.base_collector import BaseCollector, CollectorContext


FILE_RECORD_IN_USE = 0x0001
FILE_RECORD_IS_DIRECTORY = 0x0002

SHADOW_VOL_RE = re.compile(r"Shadow Copy Volume:\s*(\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d+)", re.I)
SHADOW_ID_RE = re.compile(r"Shadow Copy ID:\s*({[0-9A-Fa-f-]+})")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    # Most outputs are either ISO or "YYYY-MM-DD HH:MM:SS(.ffffff)".
    t = str(s).strip()
    if not t:
        return None
    t = t.replace("Z", "+00:00")
    if " " in t and "T" not in t:
        t = t.replace(" ", "T", 1)
    try:
        return datetime.fromisoformat(t)
    except Exception:
        # best-effort: take first 19 chars "YYYY-MM-DDTHH:MM:SS"
        m = re.match(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})", t)
        if not m:
            return None
        try:
            return datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}")
        except Exception:
            return None


def _copy_file(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    with open(src, "rb") as r, open(dst, "wb") as w:
        while True:
            chunk = r.read(8 * 1024 * 1024)
            if not chunk:
                break
            w.write(chunk)


def _run_cmd_bytes(cmd: list[str], timeout_s: int = 90) -> tuple[int, str, str]:
    p = subprocess.run(cmd, capture_output=True, text=False, timeout=timeout_s, shell=False)
    # decode safely (vssadmin output is usually ASCII/UTF-16? but bytes->replace is fine)
    stdout = (p.stdout or b"").decode(errors="replace")
    stderr = (p.stderr or b"").decode(errors="replace")
    return p.returncode, stdout, stderr


@dataclass(frozen=True)
class VssSnapshot:
    shadow_volume: str
    shadow_id: str | None


def _create_vss_snapshot(drive: str) -> VssSnapshot:
    # drive: "C" or "C:"
    d = drive.strip().rstrip("\\").rstrip(":").upper()
    rc, out, err = _run_cmd_bytes(["vssadmin", "create", "shadow", f"/for={d}:"])
    if rc != 0:
        raise RuntimeError(f"vssadmin create shadow failed (rc={rc}): {err[:200]} {out[:200]}")

    mvol = SHADOW_VOL_RE.search(out)
    if not mvol:
        raise RuntimeError("vssadmin output did not include Shadow Copy Volume")
    mid = SHADOW_ID_RE.search(out)
    return VssSnapshot(shadow_volume=mvol.group(1), shadow_id=(mid.group(1) if mid else None))


def _delete_vss_snapshot(shadow_id: str) -> None:
    rc, out, err = _run_cmd_bytes(["vssadmin", "delete", "shadows", f"/shadow={shadow_id}", "/quiet"], timeout_s=90)
    if rc != 0:
        raise RuntimeError(f"vssadmin delete shadow failed (rc={rc}): {err[:200]} {out[:200]}")


def _resolve_mft_from_path(root: Path) -> Path | None:
    if root.is_file():
        return root
    if not root.is_dir():
        return None
    # Common names: $MFT, MFT, mft
    for name in ("$MFT", "MFT", "mft", "$mft"):
        p = root / name
        if p.exists() and p.is_file():
            return p
    # fallback: any file ending with "mft"
    for p in sorted(root.glob("*mft*"), key=lambda x: x.name.lower()):
        if p.is_file():
            return p
    return None


def _run_analyze_mft(mft_path: Path, out_json: Path, *, chunk_size: int, profile: str) -> dict[str, Any]:
    # Uses analyzeMFT CLI (installed via pip): python -m analyzeMFT.cli ...
    cmd = [
        os.fspath(Path(os.sys.executable)),
        "-m",
        "analyzeMFT.cli",
        "-f",
        os.fspath(mft_path),
        "-o",
        os.fspath(out_json),
        "--json",
        "--chunk-size",
        str(chunk_size),
        "--profile",
        profile,
    ]
    rc, stdout, stderr = _run_cmd_bytes(cmd, timeout_s=600)
    return {"cmd": cmd, "returncode": rc, "stdout": stdout[-2000:], "stderr": stderr[-2000:]}


def _iter_chunk_json_files(out_json: Path) -> list[Path]:
    # analyzeMFT writes chunk files as: <output>.chunk_N.json
    return sorted(out_json.parent.glob(out_json.name + ".chunk_*.json"), key=lambda p: p.name.lower())


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def _summarize_records(
    record_lists: Iterable[list[dict[str, Any]]],
    *,
    timestomp_threshold_seconds: int,
    future_skew_seconds: int,
    ordering_threshold_seconds: int,
    max_suspicious: int,
) -> dict[str, Any]:
    total = 0
    deleted = 0
    dirs = 0
    files = 0
    suspicious: list[dict[str, Any]] = []
    now = _utc_now()

    def time_gap(a: datetime, b: datetime) -> float:
        return abs((a - b).total_seconds())

    for records in record_lists:
        for r in records:
            total += 1
            flags = int(r.get("flags") or 0)
            in_use = bool(flags & FILE_RECORD_IN_USE)
            is_dir = bool(flags & FILE_RECORD_IS_DIRECTORY)
            if not in_use:
                deleted += 1
            if is_dir:
                dirs += 1
            else:
                files += 1

            si = (r.get("si_times") or {}) if isinstance(r.get("si_times"), dict) else {}
            fn = (r.get("fn_times") or {}) if isinstance(r.get("fn_times"), dict) else {}
            # Heuristics: SI/FN mismatch, future skew, and time ordering anomalies.
            reasons: list[dict[str, Any]] = []
            score = 0
            for k in ("crtime", "mtime", "ctime", "atime"):
                a = _parse_dt(si.get(k))
                b = _parse_dt(fn.get(k))
                if a and b:
                    if time_gap(a, b) >= float(timestomp_threshold_seconds):
                        reasons.append({"type": "si_fn_mismatch", "field": k, "si": si.get(k), "fn": fn.get(k)})
                        score += 3

                # future timestamps
                x = _parse_dt(si.get(k))
                if x and (x - now).total_seconds() > float(future_skew_seconds):
                    reasons.append({"type": "future_timestamp", "field": f"si.{k}", "value": si.get(k)})
                    score += 2
                y = _parse_dt(fn.get(k))
                if y and (y - now).total_seconds() > float(future_skew_seconds):
                    reasons.append({"type": "future_timestamp", "field": f"fn.{k}", "value": fn.get(k)})
                    score += 2

            # Ordering anomaly heuristic (common expectation):
            # Create <= Modify/Change and Access can be any; flag large inversions.
            for label, times in (("si", si), ("fn", fn)):
                cr = _parse_dt(times.get("crtime"))
                mt = _parse_dt(times.get("mtime"))
                ct = _parse_dt(times.get("ctime"))
                if cr and mt and (cr - mt).total_seconds() > float(ordering_threshold_seconds):
                    reasons.append({"type": "ordering_anomaly", "field": f"{label}.crtime>mtime", "crtime": times.get("crtime"), "mtime": times.get("mtime")})
                    score += 1
                if cr and ct and (cr - ct).total_seconds() > float(ordering_threshold_seconds):
                    reasons.append({"type": "ordering_anomaly", "field": f"{label}.crtime>ctime", "crtime": times.get("crtime"), "ctime": times.get("ctime")})
                    score += 1

            if reasons and len(suspicious) < max_suspicious:
                suspicious.append(
                    {
                        "recordnum": r.get("recordnum"),
                        "filepath": r.get("filepath") or r.get("filename"),
                        "flags": flags,
                        "in_use": in_use,
                        "is_directory": is_dir,
                        "score": score,
                        "reasons": reasons,
                        "si_times": si,
                        "fn_times": fn,
                    }
                )

    return {
        "total_records_seen": total,
        "deleted_records_seen": deleted,
        "directories_seen": dirs,
        "files_seen": files,
        "suspicious_sample": sorted(suspicious, key=lambda x: int(x.get("score") or 0), reverse=True),
        "suspicious_sample_count": len(suspicious),
    }


def _write_suspicious_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "recordnum",
                "filepath",
                "in_use",
                "is_directory",
                "flags",
                "score",
                "reasons_json",
                "si_crtime",
                "si_mtime",
                "si_ctime",
                "si_atime",
                "fn_crtime",
                "fn_mtime",
                "fn_ctime",
                "fn_atime",
            ],
        )
        w.writeheader()
        for r in rows:
            si = r.get("si_times") or {}
            fn = r.get("fn_times") or {}
            w.writerow(
                {
                    "recordnum": r.get("recordnum"),
                    "filepath": r.get("filepath"),
                    "in_use": r.get("in_use"),
                    "is_directory": r.get("is_directory"),
                    "flags": r.get("flags"),
                    "score": r.get("score"),
                    "reasons_json": json.dumps(r.get("reasons") or [], ensure_ascii=False),
                    "si_crtime": (si.get("crtime") if isinstance(si, dict) else None),
                    "si_mtime": (si.get("mtime") if isinstance(si, dict) else None),
                    "si_ctime": (si.get("ctime") if isinstance(si, dict) else None),
                    "si_atime": (si.get("atime") if isinstance(si, dict) else None),
                    "fn_crtime": (fn.get("crtime") if isinstance(fn, dict) else None),
                    "fn_mtime": (fn.get("mtime") if isinstance(fn, dict) else None),
                    "fn_ctime": (fn.get("ctime") if isinstance(fn, dict) else None),
                    "fn_atime": (fn.get("atime") if isinstance(fn, dict) else None),
                }
            )


def _summarize_batch(
    records: list[dict[str, Any]],
    timestomp_threshold_seconds: int,
    future_skew_seconds: int,
    ordering_threshold_seconds: int,
    max_suspicious: int,
) -> tuple[dict[str, int], list[dict[str, Any]]]:
    """
    Worker-friendly batch summarization (for multiprocessing).
    Returns counts and top suspicious rows (unsorted).
    """
    # Reuse _summarize_records on a single batch but return lighter partials.
    summary = _summarize_records(
        [records],
        timestomp_threshold_seconds=timestomp_threshold_seconds,
        future_skew_seconds=future_skew_seconds,
        ordering_threshold_seconds=ordering_threshold_seconds,
        max_suspicious=max_suspicious,
    )
    counts = {
        "total": int(summary.get("total_records_seen") or 0),
        "deleted": int(summary.get("deleted_records_seen") or 0),
        "dirs": int(summary.get("directories_seen") or 0),
        "files": int(summary.get("files_seen") or 0),
    }
    return counts, list(summary.get("suspicious_sample") or [])


class MftParserCollector(BaseCollector):
    name = "mft_parser"
    version = "0.1.0"
    description = "Parse NTFS $MFT (path mode from copied file; live mode via VSS snapshot)."

    supports_live = True
    supports_path = True

    async def collect_live(self, ctx: CollectorContext) -> dict[str, Any]:
        drive = (ctx.get_param(self.name, "drive", "C") or "C").strip()
        cleanup = ctx.get_param_bool(self.name, "vss_cleanup", default=True)
        profile = ctx.get_param(self.name, "profile", "quick") or "quick"
        chunk_size = ctx.get_param_int(self.name, "chunk_size", 2000, min_v=100, max_v=20000)

        mod_dir = ctx.ensure_module_dir(self.name)
        snapshot = _create_vss_snapshot(drive)
        mft_src = Path(snapshot.shadow_volume + r"\$MFT")
        mft_copy = mod_dir / f"{drive.upper().rstrip(':')}_$MFT"
        try:
            await asyncio.to_thread(_copy_file, mft_src, mft_copy)
        finally:
            if cleanup and snapshot.shadow_id:
                try:
                    await asyncio.to_thread(_delete_vss_snapshot, snapshot.shadow_id)
                except Exception:
                    # don't fail collection if cleanup fails
                    pass

        return await self._analyze_mft(ctx, mft_copy, profile=profile, chunk_size=chunk_size)

    async def collect_path(self, ctx: CollectorContext, root: Path) -> dict[str, Any]:
        profile = ctx.get_param(self.name, "profile", "quick") or "quick"
        chunk_size = ctx.get_param_int(self.name, "chunk_size", 2000, min_v=100, max_v=20000)

        mft = _resolve_mft_from_path(root)
        if not mft:
            raise FileNotFoundError(f"$MFT file not found under: {root}")
        return await self._analyze_mft(ctx, mft, profile=profile, chunk_size=chunk_size)

    async def _analyze_mft(self, ctx: CollectorContext, mft_path: Path, *, profile: str, chunk_size: int) -> dict[str, Any]:
        timestomp_threshold_seconds = ctx.get_param_int(self.name, "timestomp_threshold_seconds", 86400, min_v=0, max_v=10_000_000)
        ordering_threshold_seconds = ctx.get_param_int(self.name, "ordering_threshold_seconds", 0, min_v=0, max_v=10_000_000)
        future_skew_seconds = ctx.get_param_int(self.name, "future_skew_seconds", 3600, min_v=0, max_v=10_000_000)
        max_suspicious = ctx.get_param_int(self.name, "max_suspicious", 200, min_v=0, max_v=5000)
        write_csv = ctx.get_param_bool(self.name, "write_csv", default=True)
        mp_enabled = ctx.get_param_bool(self.name, "multiprocessing", default=True)
        mp_records_per_task = ctx.get_param_int(self.name, "mp_records_per_task", 100_000, min_v=10_000, max_v=5_000_000)
        mp_workers = ctx.get_param_int(self.name, "mp_workers", (os.cpu_count() or 4), min_v=1, max_v=128)
        process_chunk_files_limit = ctx.get_param_int(self.name, "process_chunk_files_limit", 50, min_v=0, max_v=1_000_000)

        mod_dir = ctx.ensure_module_dir(self.name)
        out_json = mod_dir / "analyzeMFT.json"

        cmdres = await asyncio.to_thread(_run_analyze_mft, mft_path, out_json, chunk_size=chunk_size, profile=profile)
        if int(cmdres.get("returncode") or 1) != 0:
            raise RuntimeError(f"analyzeMFT failed: {cmdres}")

        chunk_files = _iter_chunk_json_files(out_json)
        if process_chunk_files_limit > 0:
            chunk_files = chunk_files[:process_chunk_files_limit]

        # Summarize without loading everything into one list.
        total = deleted = dirs = files = 0
        suspicious_all: list[dict[str, Any]] = []

        async def handle_records(records: list[dict[str, Any]]) -> None:
            nonlocal total, deleted, dirs, files, suspicious_all
            part = _summarize_records(
                [records],
                timestomp_threshold_seconds=timestomp_threshold_seconds,
                future_skew_seconds=future_skew_seconds,
                ordering_threshold_seconds=ordering_threshold_seconds,
                max_suspicious=max_suspicious,
            )
            total += int(part.get("total_records_seen") or 0)
            deleted += int(part.get("deleted_records_seen") or 0)
            dirs += int(part.get("directories_seen") or 0)
            files += int(part.get("files_seen") or 0)
            suspicious_all.extend(list(part.get("suspicious_sample") or []))

        if chunk_files:
            # Read each chunk file and process in batches of mp_records_per_task.
            if mp_enabled:
                from concurrent.futures import ProcessPoolExecutor
                import heapq

                def _score(r: dict[str, Any]) -> int:
                    try:
                        return int(r.get("score") or 0)
                    except Exception:
                        return 0

                loop = asyncio.get_running_loop()
                with ProcessPoolExecutor(max_workers=mp_workers) as ex:
                    futures = []
                    for p in chunk_files:
                        records = await asyncio.to_thread(_load_json, p)
                        if not isinstance(records, list):
                            continue
                        # split into ~100k-sized tasks
                        batch: list[dict[str, Any]] = []
                        for item in records:
                            if isinstance(item, dict):
                                batch.append(item)
                            if len(batch) >= mp_records_per_task:
                                futures.append(
                                    loop.run_in_executor(
                                        ex,
                                        _summarize_batch,
                                        batch,
                                        timestomp_threshold_seconds,
                                        future_skew_seconds,
                                        ordering_threshold_seconds,
                                        max_suspicious,
                                    )
                                )
                                batch = []
                        if batch:
                            futures.append(
                                loop.run_in_executor(
                                    ex,
                                    _summarize_batch,
                                    batch,
                                    timestomp_threshold_seconds,
                                    future_skew_seconds,
                                    ordering_threshold_seconds,
                                    max_suspicious,
                                )
                            )

                    for fut in await asyncio.gather(*futures):
                        counts, sus = fut
                        total += counts["total"]
                        deleted += counts["deleted"]
                        dirs += counts["dirs"]
                        files += counts["files"]
                        suspicious_all.extend(sus)

                # keep only top max_suspicious overall
                if max_suspicious > 0 and suspicious_all:
                    suspicious_all = heapq.nlargest(max_suspicious, suspicious_all, key=_score)
            else:
                for p in chunk_files:
                    records = await asyncio.to_thread(_load_json, p)
                    if isinstance(records, list):
                        # split but single-process
                        batch: list[dict[str, Any]] = []
                        for item in records:
                            if isinstance(item, dict):
                                batch.append(item)
                            if len(batch) >= mp_records_per_task:
                                await handle_records(batch)
                                batch = []
                        if batch:
                            await handle_records(batch)
        elif out_json.exists():
            # Fallback: may be a full JSON dump of MftRecord __dict__ (less ideal)
            raw = await asyncio.to_thread(_load_json, out_json)
            if isinstance(raw, list):
                await handle_records([r for r in raw if isinstance(r, dict)])

        summary = {
            "total_records_seen": total,
            "deleted_records_seen": deleted,
            "directories_seen": dirs,
            "files_seen": files,
            "suspicious_sample": suspicious_all,
            "suspicious_sample_count": len(suspicious_all),
        }

        suspicious_path = mod_dir / "suspicious_sample.json"
        suspicious_csv_path = mod_dir / "suspicious_sample.csv"
        await asyncio.to_thread(
            suspicious_path.write_text,
            json.dumps(summary.get("suspicious_sample", []), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        if write_csv:
            await asyncio.to_thread(_write_suspicious_csv, suspicious_csv_path, summary.get("suspicious_sample", []))

        return {
            "mft_path": str(mft_path),
            "analyzeMFT": {
                "output_json": str(out_json),
                "chunk_files_count": len(chunk_files),
                "cmd": cmdres.get("cmd"),
            },
            "config": {
                "profile": profile,
                "chunk_size": chunk_size,
                "timestomp_threshold_seconds": timestomp_threshold_seconds,
                "ordering_threshold_seconds": ordering_threshold_seconds,
                "future_skew_seconds": future_skew_seconds,
                "max_suspicious": max_suspicious,
                "write_csv": write_csv,
                "multiprocessing": mp_enabled,
                "mp_records_per_task": mp_records_per_task,
                "mp_workers": mp_workers,
                "process_chunk_files_limit": process_chunk_files_limit,
            },
            "summary": summary,
            "artifacts": {
                "analyzeMFT_json": str(out_json),
                "suspicious_sample_json": str(suspicious_path),
                "suspicious_sample_csv": (str(suspicious_csv_path) if write_csv else None),
            },
        }


def get_collector() -> BaseCollector:
    return MftParserCollector()

