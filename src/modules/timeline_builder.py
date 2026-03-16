from __future__ import annotations

import asyncio
import csv
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from src.core.base_collector import CollectorContext, PluginCollector


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    t = str(s).strip()
    if not t:
        return None
    t = t.replace("Z", "+00:00")
    if " " in t and "T" not in t:
        t = t.replace(" ", "T", 1)
    try:
        dt = datetime.fromisoformat(t)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _iter_json_files(folder: Path, pattern: str) -> list[Path]:
    if not folder.exists():
        return []
    return sorted(folder.glob(pattern), key=lambda p: p.name.lower())


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


@dataclass(frozen=True)
class TimelineEvent:
    ts_utc: str
    source: str
    type: str
    message: str
    data: dict[str, Any]


def _to_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def _collect_evtx_events(evtx_module_dir: Path, *, event_ids: set[int] | None, limit: int) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    files = _iter_json_files(evtx_module_dir, "*.sample.json")
    for f in files:
        payload = _load_json(f)
        records = payload.get("records") or []
        for r in records:
            sysd = r.get("system") or {}
            eid = sysd.get("event_id")
            try:
                eid_i = int(eid)
            except Exception:
                continue
            if event_ids and eid_i not in event_ids:
                continue
            t = _parse_dt(sysd.get("time_created_utc"))
            if not t:
                continue
            msg = f"EventID {eid_i} ({sysd.get('channel')})"
            events.append(
                TimelineEvent(
                    ts_utc=_to_iso(t),
                    source="event_log_collector",
                    type=f"evtx:{eid_i}",
                    message=msg,
                    data={
                        "event_id": eid_i,
                        "channel": sysd.get("channel"),
                        "computer": sysd.get("computer"),
                        "provider": sysd.get("provider"),
                        "record_id": sysd.get("record_id"),
                        "event_data": r.get("event_data") or {},
                        "sample_file": str(f),
                    },
                )
            )
            if len(events) >= limit:
                return events
    return events


def _collect_mft_creates(mft_module_dir: Path, *, limit: int) -> list[tuple[datetime, dict[str, Any]]]:
    out: list[tuple[datetime, dict[str, Any]]] = []
    # Current pipeline writes lightweight JSON artifacts (no external MFT libs).
    # Prefer suspicious sample if available (timestomp/future/ordering flags).
    sus = mft_module_dir / "suspicious_sample.json"
    if sus.exists():
        rows = _load_json(sus)
        if isinstance(rows, list):
            for r in rows:
                if not isinstance(r, dict):
                    continue
                fn = r.get("fn_times") or {}
                dt = _parse_dt((fn.get("crtime") if isinstance(fn, dict) else None))
                if dt:
                    out.append((dt, r))
                    if len(out) >= limit:
                        return out

    # Fallback: deleted record samples (if produced by mft_collector)
    deleted = mft_module_dir / "deleted_sample.json"
    if deleted.exists():
        rows = _load_json(deleted)
        if isinstance(rows, list):
            for r in rows:
                if not isinstance(r, dict):
                    continue
                dt = _parse_dt(r.get("created"))
                if dt:
                    out.append((dt, r))
                    if len(out) >= limit:
                        return out
    return out


def _correlate(
    evtx: list[TimelineEvent],
    mft_creates: list[tuple[datetime, dict[str, Any]]],
    *,
    window_seconds: int,
    max_pairs: int,
) -> list[TimelineEvent]:
    # naive correlation: pair any MFT create within +/- window around evtx event
    pairs: list[TimelineEvent] = []
    mft_sorted = sorted(mft_creates, key=lambda x: x[0])
    for e in evtx:
        et = _parse_dt(e.ts_utc)
        if not et:
            continue
        lo = et.timestamp() - window_seconds
        hi = et.timestamp() + window_seconds
        for mt, m in mft_sorted:
            ts = mt.timestamp()
            if ts < lo:
                continue
            if ts > hi:
                break
            pairs.append(
                TimelineEvent(
                    ts_utc=e.ts_utc,
                    source="timeline_builder",
                    type="correlation",
                    message=f"MFT create near {e.type}",
                    data={"event": e.data, "mft": m, "window_seconds": window_seconds},
                )
            )
            if len(pairs) >= max_pairs:
                return pairs
    return pairs


def _write_jsonl(path: Path, events: Iterable[TimelineEvent]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e.__dict__, ensure_ascii=False) + "\n")


def _write_csv(path: Path, events: Iterable[TimelineEvent]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["ts_utc", "source", "type", "message", "data_json"])
        w.writeheader()
        for e in events:
            w.writerow(
                {
                    "ts_utc": e.ts_utc,
                    "source": e.source,
                    "type": e.type,
                    "message": e.message,
                    "data_json": json.dumps(e.data, ensure_ascii=False),
                }
            )


class TimelineBuilderCollector(PluginCollector):
    name = "timeline_builder"
    version = "0.1.0"
    description = "Build a unified timeline from MFT and Event Logs (and correlate within a time window)."

    supports_live = True
    supports_path = True

    async def collect_live(self, ctx: CollectorContext) -> dict[str, Any]:
        return await self._build(ctx)

    async def collect_path(self, ctx: CollectorContext, root: Path) -> dict[str, Any]:
        return await self._build(ctx)

    async def _build(self, ctx: CollectorContext) -> dict[str, Any]:
        # Inputs are artifacts created by other modules in the same run output_dir.
        evtx_dir = ctx.output_dir / "modules" / "event_log_collector"
        mft_dir = ctx.output_dir / "modules" / "mft_parser"
        mod_dir = ctx.ensure_module_dir(self.name)

        window_seconds = ctx.get_param_int(self.name, "window_seconds", 300, min_v=0, max_v=86_400)
        max_pairs = ctx.get_param_int(self.name, "max_pairs", 500, min_v=0, max_v=50_000)
        evtx_limit = ctx.get_param_int(self.name, "evtx_limit", 5000, min_v=0, max_v=200_000)
        mft_limit = ctx.get_param_int(self.name, "mft_limit", 200_000, min_v=0, max_v=5_000_000)
        event_ids_raw = ctx.get_param_list(self.name, "event_ids", default=["4624", "4688"])
        event_ids: set[int] | None = None
        if event_ids_raw:
            parsed: set[int] = set()
            for s in event_ids_raw:
                try:
                    parsed.add(int(str(s).strip()))
                except Exception:
                    continue
            event_ids = parsed or None

        evtx_events = await asyncio.to_thread(_collect_evtx_events, evtx_dir, event_ids=event_ids, limit=evtx_limit)
        mft_creates = await asyncio.to_thread(_collect_mft_creates, mft_dir, limit=mft_limit)

        # Convert MFT creates to timeline events
        mft_events: list[TimelineEvent] = []
        for dt, m in mft_creates:
            mft_events.append(
                TimelineEvent(
                    ts_utc=_to_iso(dt),
                    source="mft_parser",
                    type="mft:create",
                    message=str(m.get("filepath") or ""),
                    data=m,
                )
            )

        corr = await asyncio.to_thread(_correlate, evtx_events, mft_creates, window_seconds=window_seconds, max_pairs=max_pairs)

        all_events = sorted([*evtx_events, *mft_events, *corr], key=lambda e: e.ts_utc)
        out_jsonl = mod_dir / "timeline.jsonl"
        out_csv = mod_dir / "timeline.csv"
        await asyncio.to_thread(_write_jsonl, out_jsonl, all_events)
        await asyncio.to_thread(_write_csv, out_csv, all_events)

        return {
            "inputs": {
                "event_log_module_dir": str(evtx_dir),
                "mft_module_dir": str(mft_dir),
                "event_ids": sorted(list(event_ids)) if event_ids else [],
            },
            "config": {
                "window_seconds": window_seconds,
                "max_pairs": max_pairs,
                "evtx_limit": evtx_limit,
                "mft_limit": mft_limit,
            },
            "counts": {
                "evtx_events": len(evtx_events),
                "mft_create_events": len(mft_events),
                "correlations": len(corr),
                "total": len(all_events),
            },
            "artifacts": {"timeline_jsonl": str(out_jsonl), "timeline_csv": str(out_csv)},
        }


def get_collector() -> PluginCollector:
    return TimelineBuilderCollector()

