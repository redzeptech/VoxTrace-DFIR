from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

from src.core.base_collector import CollectorContext, PluginCollector
from src.core.ntfs_mft import iter_mft_entries


class MFTScanner(PluginCollector):
    """
    Focused MFT triage:
    - Detect deleted records still present in $MFT (flags & FILE_RECORD_IN_USE == 0)

    Live mode note:
    - Direct `\\\\.\\C:` parsing requires NTFS volume parsing or a helper collector.
      For real live acquisition, use `mft_collector` (raw volume extraction) or `mft_parser` (VSS copy),
      then run this scanner on the extracted $MFT in --path mode.
    """

    name = "mft_scanner"
    version = "0.1.0"
    description = "Detect deleted-but-present file records from an $MFT file (path mode)."

    supports_live = True
    supports_path = True

    def collect(self):
        # MFT is locked/hidden; live raw access would require deeper NTFS handling.
        if getattr(self, "mode", None) == "live":
            return r"\\.\C:"
        return str(getattr(self, "source_path", "") or "")

    def parse(self):
        print("[*] Initiating Deep MFT Analysis...")
        # For main.py integration, keep `results` as a list of per-file findings.
        findings: list[dict[str, Any]] = []

        if getattr(self, "mode", None) != "path":
            findings.append(
                {
                    "info": "Live MFT access requires raw NTFS parsing. Use mft_collector/mft_parser to extract $MFT, then run mft_scanner in --path mode."
                }
            )
            self.results = findings
            return self.results

        src = self.collect()
        if not src:
            findings.append({"error": "source_path is required in path mode"})
            self.results = findings
            return self.results

        mft_path = Path(src)
        if mft_path.is_dir():
            # common name
            candidate = mft_path / "$MFT"
            mft_path = candidate if candidate.exists() else mft_path

        if not mft_path.exists() or not mft_path.is_file():
            findings.append({"error": f"$MFT file not found: {mft_path}"})
            self.results = findings
            return self.results

        # Params
        limit_deleted = 50
        try:
            limit_deleted = int(os.getenv("VOXTRACE_MFT_SCANNER_LIMIT", "50"))
        except Exception:
            limit_deleted = 50
        limit_deleted = max(1, min(limit_deleted, 5000))

        deleted_hits: list[dict[str, Any]] = []
        total_seen = 0
        deleted_seen = 0
        for ent in iter_mft_entries(mft_path):
            total_seen += 1
            if not ent.in_use:
                deleted_seen += 1
                deleted_hits.append(
                    {
                        "status": "DELETED",
                        "filename": ent.filename,
                        "created": (ent.fn_times.get("crtime") if ent.fn_times else None) or (ent.si_times.get("crtime") if ent.si_times else None),
                        "recordnum": ent.recordnum,
                        "parent_ref": ent.parent_ref,
                    }
                )
                if len(deleted_hits) >= limit_deleted:
                    break

        findings.append(
            {
                "type": "MFT_SCAN_META",
                "source_mft": str(mft_path),
                "total_records_seen": total_seen,
                "deleted_records_seen": deleted_seen,
                "deleted_records_sample_count": len(deleted_hits),
            }
        )

        # Main-friendly shape: list of deleted file entries (each has status/filename/created)
        if deleted_hits:
            findings.extend(deleted_hits)
        else:
            findings.append(
                {
                    "info": "No deleted records found in sample (or parser produced no chunk output).",
                    "source_mft": str(mft_path),
                }
            )

        self.results = findings
        return self.results

    async def collect_live(self, ctx: CollectorContext) -> dict[str, Any]:
        ctx.ensure_module_dir(self.name)
        return await asyncio.to_thread(self.parse)

    async def collect_path(self, ctx: CollectorContext, root: Path) -> dict[str, Any]:
        ctx.ensure_module_dir(self.name)
        return await asyncio.to_thread(self.parse)


def get_collector() -> PluginCollector:
    return MFTScanner()

