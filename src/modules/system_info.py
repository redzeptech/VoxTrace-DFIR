from __future__ import annotations

import asyncio
import locale
import os
import platform
import socket
import subprocess
from pathlib import Path
from typing import Any

from src.core.base_collector import BaseCollector, CollectorContext


def _run_cmd(cmd: list[str], timeout_s: int = 20) -> dict[str, Any]:
    try:
        # Use bytes to avoid platform codepage decode crashes, then decode safely.
        p = subprocess.run(cmd, capture_output=True, text=False, timeout=timeout_s, shell=False)
        enc = locale.getpreferredencoding(False) or "utf-8"
        stdout = (p.stdout or b"").decode(enc, errors="replace")
        stderr = (p.stderr or b"").decode(enc, errors="replace")
        return {
            "cmd": cmd,
            "returncode": p.returncode,
            "stdout": stdout[:20000],
            "stderr": stderr[:20000],
        }
    except Exception as e:
        return {"cmd": cmd, "error": str(e)}


class SystemInfoCollector(BaseCollector):
    name = "system_info"
    version = "0.1.0"
    description = "Collect basic live system information (Windows-friendly)."

    supports_live = True
    supports_path = False

    async def collect_live(self, ctx: CollectorContext) -> dict[str, Any]:
        mod_dir = ctx.ensure_module_dir(self.name)

        data: dict[str, Any] = {
            "hostname": socket.gethostname(),
            "fqdn": socket.getfqdn(),
            "username": os.getenv("USERNAME") or os.getenv("USER") or "",
            "domain": os.getenv("USERDOMAIN") or "",
            "os": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "platform": platform.platform(),
                "machine": platform.machine(),
                "processor": platform.processor(),
            },
            "python": {
                "version": platform.python_version(),
                "implementation": platform.python_implementation(),
            },
            "env": {
                "computername": os.getenv("COMPUTERNAME") or "",
                "windir": os.getenv("WINDIR") or "",
                "systemroot": os.getenv("SystemRoot") or "",
            },
        }

        # Windows: systeminfo provides a useful snapshot. Not always available.
        sysinfo = await asyncio.to_thread(_run_cmd, ["systeminfo"], 30)
        data["commands"] = {"systeminfo": sysinfo}

        # Persist raw command outputs for offline review
        out_path = mod_dir / "systeminfo.txt"
        raw = sysinfo.get("stdout") or ""
        if raw:
            await asyncio.to_thread(out_path.write_text, raw, encoding="utf-8", errors="ignore")
            data["artifacts"] = {"systeminfo_txt": str(out_path)}
        else:
            data["artifacts"] = {}

        return data

    async def collect_path(self, ctx: CollectorContext, root: Path) -> dict[str, Any]:
        raise NotImplementedError("system_info supports only --live mode")


def get_collector() -> BaseCollector:
    return SystemInfoCollector()

