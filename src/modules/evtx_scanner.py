from __future__ import annotations

import asyncio
import glob
import os
import re
from pathlib import Path
from typing import Any

from src.core.base_collector import CollectorContext, PluginCollector


class EVTXScanner(PluginCollector):
    name = "evtx_scanner"
    version = "0.1.0"
    description = "Scan EVTX inventory and sample critical Event IDs from Security.evtx."

    supports_live = True
    supports_path = True

    # Critical Event IDs
    CRITICAL_EVENTS: dict[int, str] = {
        4624: "Successful Logon",
        4688: "New Process Created",
        1102: "Audit Log Cleared (STREAK!)",
        4720: "User Account Created",
    }

    def collect(self):
        if getattr(self, "mode", None) == "live":
            return r"C:\Windows\System32\winevt\Logs"
        return str(getattr(self, "source_path", "") or "")

    def parse(self):
        path = self.collect()
        if not path or not os.path.exists(path):
            self.results = {"error": f"{path} not found."}
            return self.results

        limit = 10
        try:
            limit = int(os.getenv("VOXTRACE_EVTX_SCANNER_LIMIT", "10"))
        except Exception:
            limit = 10

        log_files = glob.glob(os.path.join(path, "*.evtx"))
        security_path = os.path.join(path, "Security.evtx")

        parsed_events: list[dict[str, Any]] = []
        errors: list[str] = []

        event_id_res = {
            eid: re.compile(rf"<EventID(?:\s+Qualifiers=\"\d+\")?>\s*{eid}\s*</EventID>", re.IGNORECASE)
            for eid in self.CRITICAL_EVENTS
        }
        ts_re = re.compile(r'SystemTime="([^"]+)"', re.IGNORECASE)

        if os.path.exists(security_path):
            try:
                from evtx import PyEvtxParser  # type: ignore

                parser = PyEvtxParser(security_path)
                for rec in parser.records():
                    xml = rec.get("data") or ""
                    if not xml:
                        continue
                    hit_id: int | None = None
                    for eid, rx in event_id_res.items():
                        if rx.search(xml):
                            hit_id = eid
                            break
                    if hit_id is None:
                        continue

                    # Prefer record timestamp, fallback to SystemTime in XML
                    ts = rec.get("timestamp")
                    if not ts:
                        m = ts_re.search(xml)
                        ts = m.group(1) if m else None

                    parsed_events.append(
                        {
                            "event_id": hit_id,
                            "description": self.CRITICAL_EVENTS.get(hit_id, ""),
                            "timestamp": ts,
                            "source": security_path,
                        }
                    )
                    if len(parsed_events) >= limit:
                        break
            except PermissionError:
                errors.append("Permission denied reading Security.evtx (try Administrator).")
            except Exception as e:
                errors.append(f"Security.evtx parse error: {e}")
        else:
            errors.append("Security.evtx not found in target folder.")

        self.results = {
            "total_logs_found": len(log_files),
            "files": [os.path.basename(f) for f in log_files[:5]],
            "security_evtx": security_path,
            "critical_event_ids": self.CRITICAL_EVENTS,
            "critical_hits": parsed_events,
            "critical_hits_count": len(parsed_events),
        }
        if errors:
            self.results["errors"] = errors
        return self.results

    async def collect_live(self, ctx: CollectorContext) -> dict[str, Any]:
        return await asyncio.to_thread(self.parse)

    async def collect_path(self, ctx: CollectorContext, root: Path) -> dict[str, Any]:
        return await asyncio.to_thread(self.parse)


def get_collector() -> PluginCollector:
    return EVTXScanner()

