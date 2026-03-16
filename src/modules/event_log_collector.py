from __future__ import annotations

import asyncio
import locale
import os
import subprocess
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from src.core.base_collector import BaseCollector, CollectorContext


def _parse_event_xml(xml_text: str) -> dict[str, Any]:
    """
    Minimal, fast extraction of common fields from Windows Event XML.
    Keeps the original XML in case some fields are missing.
    """
    out: dict[str, Any] = {"system": {}, "event_data": {}, "xml": xml_text}
    try:
        root = ET.fromstring(xml_text)
    except Exception as e:
        out["parse_error"] = str(e)
        return out

    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    def fx(path: str) -> Any:
        el = root.find(path)
        return el.text if el is not None else None

    sys_el = root.find(f"{ns}System")
    if sys_el is not None:
        provider = sys_el.find(f"{ns}Provider")
        time_created = sys_el.find(f"{ns}TimeCreated")
        event_id = sys_el.find(f"{ns}EventID")

        out["system"] = {
            "provider": provider.attrib.get("Name") if provider is not None else None,
            "event_id": int(event_id.text) if event_id is not None and (event_id.text or "").isdigit() else (event_id.text if event_id is not None else None),
            "channel": fx(f"{ns}System/{ns}Channel"),
            "computer": fx(f"{ns}System/{ns}Computer"),
            "level": fx(f"{ns}System/{ns}Level"),
            "task": fx(f"{ns}System/{ns}Task"),
            "opcode": fx(f"{ns}System/{ns}Opcode"),
            "record_id": fx(f"{ns}System/{ns}EventRecordID"),
            "time_created_utc": time_created.attrib.get("SystemTime") if time_created is not None else None,
        }

    ed_el = root.find(f"{ns}EventData")
    if ed_el is not None:
        for d in ed_el.findall(f"{ns}Data"):
            key = d.attrib.get("Name") or ""
            val = d.text or ""
            if key:
                out["event_data"][key] = val

    return out


def _resolve_evtx_target(root: Path) -> Path | None:
    if root.is_file() and root.suffix.lower() == ".evtx":
        return root
    if root.is_dir():
        sec = root / "Security.evtx"
        if sec.exists():
            return sec
        # fallback: first evtx
        for p in sorted(root.glob("*.evtx"), key=lambda x: x.name.lower()):
            return p
    return None


def _read_evtx_records(evtx_path: Path, limit: int) -> dict[str, Any]:
    # python-evtx provides Evtx.Evtx
    from Evtx.Evtx import Evtx  # type: ignore

    records: list[dict[str, Any]] = []
    with Evtx(str(evtx_path)) as log:
        for i, rec in enumerate(log.records()):
            if i >= limit:
                break
            xml_text = rec.xml()
            records.append(_parse_event_xml(xml_text))

    return {
        "target": str(evtx_path),
        "record_limit": limit,
        "records": records,
    }


def _resolve_evtx_targets(root: Path, channels: list[str]) -> list[Path]:
    if root.is_file() and root.suffix.lower() == ".evtx":
        return [root]
    if not root.is_dir():
        return []
    if channels:
        out: list[Path] = []
        for ch in channels:
            p = root / f"{ch}.evtx"
            if p.exists():
                out.append(p)
        return out
    # Default behavior: prefer Security.evtx, else first .evtx
    t = _resolve_evtx_target(root)
    return [t] if t else []


def _run_cmd_bytes(cmd: list[str], timeout_s: int = 30) -> tuple[int, str, str]:
    p = subprocess.run(cmd, capture_output=True, text=False, timeout=timeout_s, shell=False)
    enc = locale.getpreferredencoding(False) or "utf-8"
    stdout = (p.stdout or b"").decode(enc, errors="replace")
    stderr = (p.stderr or b"").decode(enc, errors="replace")
    return p.returncode, stdout, stderr


def _read_wevtutil_events(channel: str, limit: int) -> dict[str, Any]:
    # Returns XML. Depending on Windows version, output may already be wrapped.
    rc, stdout, stderr = _run_cmd_bytes(["wevtutil", "qe", channel, "/f:xml", f"/c:{limit}"], timeout_s=45)
    if rc != 0:
        if rc == 5 or "Access is denied" in stderr or "Erişim engellendi" in stderr:
            raise PermissionError(f"wevtutil qe access denied for channel={channel}")
        raise RuntimeError(f"wevtutil qe failed (rc={rc}): {stderr[:200]}")

    xml = stdout.strip()
    if not xml:
        return {"channel": channel, "record_limit": limit, "records": []}

    if not xml.lstrip().startswith("<Events"):
        xml = f"<Events>{xml}</Events>"

    try:
        root = ET.fromstring(xml)
    except Exception as e:
        raise RuntimeError(f"Failed to parse wevtutil XML: {e}")

    records: list[dict[str, Any]] = []
    for ev in list(root):
        try:
            ev_xml = ET.tostring(ev, encoding="unicode")
        except Exception:
            continue
        records.append(_parse_event_xml(ev_xml))

    return {
        "channel": channel,
        "record_limit": limit,
        "records": records,
    }


def _filter_records_by_event_ids(records: list[dict[str, Any]], event_ids: set[int] | None) -> list[dict[str, Any]]:
    if not event_ids:
        return records
    out: list[dict[str, Any]] = []
    for r in records:
        sysd = r.get("system") or {}
        eid = sysd.get("event_id")
        try:
            eid_i = int(eid)
        except Exception:
            continue
        if eid_i in event_ids:
            out.append(r)
    return out


class EventLogCollector(BaseCollector):
    name = "event_log_collector"
    version = "0.1.0"
    description = "Parse Windows EVTX (default: Security.evtx) and emit JSON records."

    supports_live = True
    supports_path = True

    async def collect_live(self, ctx: CollectorContext) -> dict[str, Any]:
        # Standard live path
        folder = Path(os.environ.get("WINEVT_LOGS", r"C:\Windows\System32\winevt\Logs"))
        return await self._collect_from_root(ctx, folder, live=True)

    async def collect_path(self, ctx: CollectorContext, root: Path) -> dict[str, Any]:
        return await self._collect_from_root(ctx, root, live=False)

    async def _collect_from_root(self, ctx: CollectorContext, root: Path, *, live: bool) -> dict[str, Any]:
        limit = ctx.get_param_int(self.name, "limit", int(os.getenv("VOXTRACE_EVTX_LIMIT", "100")), min_v=1, max_v=5000)
        channels = ctx.get_param_list(self.name, "channels", default=["Security"])
        inline_records = ctx.get_param_bool(self.name, "inline_records", default=True)
        prefer_wevtutil = ctx.get_param_bool(self.name, "prefer_wevtutil", default=False)
        allow_partial = ctx.get_param_bool(self.name, "allow_partial", default=True)
        event_ids_raw = ctx.get_param_list(self.name, "event_ids", default=[])
        event_ids: set[int] | None = None
        if event_ids_raw:
            parsed: set[int] = set()
            for s in event_ids_raw:
                try:
                    parsed.add(int(str(s).strip()))
                except Exception:
                    continue
            event_ids = parsed or None

        targets = _resolve_evtx_targets(root, channels)
        if not targets and not (live and channels):
            raise FileNotFoundError(f"No matching .evtx found under: {root}")

        mod_dir = ctx.ensure_module_dir(self.name)

        parsed: list[dict[str, Any]] = []
        artifacts: dict[str, str] = {}
        module_errors: list[str] = []

        # In live mode, EVTX files are often permission-protected (especially Security.evtx).
        # Fallback to `wevtutil qe` which can return records as XML without direct file access.
        if live and channels and (prefer_wevtutil or not targets):
            for ch in channels:
                try:
                    d = await asyncio.to_thread(_read_wevtutil_events, ch, limit)
                    d["records"] = _filter_records_by_event_ids(d.get("records") or [], event_ids)
                    stem = ch
                    out_path = mod_dir / f"{stem}.sample.json"
                    await asyncio.to_thread(out_path.write_text, _json_dumps(d), encoding="utf-8")
                    artifacts[f"{stem}_sample_json"] = str(out_path)
                    d["target"] = f"wevtutil://{ch}"
                    parsed.append(d)
                except PermissionError as e:
                    msg = f"access denied: {ch} ({e})"
                    if not allow_partial:
                        raise
                    module_errors.append(msg)
        else:
            # Try python-evtx from files; if permission denied in live mode, fallback per-channel to wevtutil.
            for t in targets:
                stem = Path(t).stem
                try:
                    d = await asyncio.to_thread(_read_evtx_records, t, limit)
                    d["records"] = _filter_records_by_event_ids(d.get("records") or [], event_ids)
                    out_path = mod_dir / f"{stem}.sample.json"
                    await asyncio.to_thread(out_path.write_text, _json_dumps(d), encoding="utf-8")
                    artifacts[f"{stem}_sample_json"] = str(out_path)
                    parsed.append(d)
                except PermissionError:
                    if not live:
                        raise
                    ch = stem
                    try:
                        d = await asyncio.to_thread(_read_wevtutil_events, ch, limit)
                        d["records"] = _filter_records_by_event_ids(d.get("records") or [], event_ids)
                        out_path = mod_dir / f"{ch}.sample.json"
                        await asyncio.to_thread(out_path.write_text, _json_dumps(d), encoding="utf-8")
                        artifacts[f"{ch}_sample_json"] = str(out_path)
                        d["target"] = f"wevtutil://{ch}"
                        parsed.append(d)
                    except PermissionError as e:
                        msg = f"access denied: {ch} ({e})"
                        if not allow_partial:
                            raise
                        module_errors.append(msg)

        evtx_summaries: list[dict[str, Any]] = []
        inline: dict[str, list[dict[str, Any]]] = {}

        for d in parsed:
            target = str(d.get("target") or "")
            stem = "unknown"
            if target.startswith("wevtutil://"):
                stem = target.split("://", 1)[1]
            else:
                stem = Path(target).stem if target else "unknown"
            evtx_summaries.append(
                {
                    "target": target,
                    "record_limit": d["record_limit"],
                    "record_count": len(d["records"]),
                }
            )
            if inline_records:
                inline[stem] = d["records"]

        out: dict[str, Any] = {
            "source_root": str(root),
            "config": {
                "channels": channels,
                "limit_per_file": limit,
                "inline_records": inline_records,
                "prefer_wevtutil": prefer_wevtutil,
                "event_ids": sorted(list(event_ids)) if event_ids else [],
                "allow_partial": allow_partial,
            },
            "evtx": evtx_summaries,
            "artifacts": artifacts,
        }
        if module_errors:
            out["errors"] = module_errors
        if inline_records:
            out["records_by_file"] = inline
        return out


def _json_dumps(obj: Any) -> str:
    import json

    return json.dumps(obj, ensure_ascii=False, indent=2)


def get_collector() -> BaseCollector:
    return EventLogCollector()

