from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

CollectorMode = Literal["live", "path"]


class BaseCollector(ABC):
    def __init__(self, mode: str = "live", source_path: str | None = None):
        self.mode = mode
        self.source_path = source_path
        self.results: Any = []

    @abstractmethod
    def collect(self):
        """Kanıt toplama mantığı (Dosya kopyalama veya ham okuma)"""
        raise NotImplementedError

    @abstractmethod
    def parse(self):
        """Toplanan kanıtı analiz etme ve normalize etme"""
        raise NotImplementedError

    def get_report(self):
        return {"module": self.__class__.__name__, "mode": self.mode, "data": self.results}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass(frozen=True)
class CollectorContext:
    tool: str
    tool_version: str
    run_id: str
    case_id: str
    mode: CollectorMode
    output_dir: Path
    source_path: Path | None
    params: dict[str, dict[str, str]]

    def ensure_module_dir(self, module_name: str) -> Path:
        d = self.output_dir / "modules" / module_name
        d.mkdir(parents=True, exist_ok=True)
        return d

    def get_param(self, module: str, key: str, default: str | None = None) -> str | None:
        return (self.params.get(module) or {}).get(key, default)

    def get_param_bool(self, module: str, key: str, default: bool = False) -> bool:
        v = self.get_param(module, key, None)
        if v is None:
            return bool(default)
        s = str(v).strip().lower()
        if s in {"1", "true", "yes", "y", "on"}:
            return True
        if s in {"0", "false", "no", "n", "off"}:
            return False
        return bool(default)

    def get_param_int(
        self, module: str, key: str, default: int, *, min_v: int | None = None, max_v: int | None = None
    ) -> int:
        v = self.get_param(module, key, None)
        try:
            out = int(str(v)) if v is not None else int(default)
        except Exception:
            out = int(default)
        if min_v is not None:
            out = max(min_v, out)
        if max_v is not None:
            out = min(max_v, out)
        return out

    def get_param_list(self, module: str, key: str, default: list[str] | None = None) -> list[str]:
        v = self.get_param(module, key, None)
        if v is None:
            return list(default or [])
        parts = [p.strip() for p in str(v).split(",")]
        return [p for p in parts if p]


@dataclass(frozen=True)
class CollectorResult:
    schema_version: str
    module: str
    module_version: str
    mode: CollectorMode
    started_at: str
    ended_at: str
    status: Literal["ok", "error", "skipped"]
    data: dict[str, Any]
    error: str | None = None


class PluginCollector(BaseCollector):
    """
    Plugin contract:
    - Place collectors under `src/modules/`
    - Export either:
      - `COLLECTOR = <instance>` OR
      - `def get_collector() -> PluginCollector`
    """

    name: str
    version: str = "0.1.0"
    description: str = ""

    supports_live: bool = False
    supports_path: bool = False

    def __init__(self, mode: str = "live", source_path: str | None = None):
        super().__init__(mode=mode, source_path=source_path)

    def can_run(self, mode: CollectorMode) -> bool:
        return (mode == "live" and self.supports_live) or (mode == "path" and self.supports_path)

    async def run(self, ctx: CollectorContext) -> CollectorResult:
        started_at = utc_now_iso()
        try:
            if not self.can_run(ctx.mode):
                return CollectorResult(
                    schema_version="voxtrace.collector_result.v1",
                    module=self.name,
                    module_version=self.version,
                    mode=ctx.mode,
                    started_at=started_at,
                    ended_at=utc_now_iso(),
                    status="skipped",
                    data={},
                    error=f"collector does not support mode={ctx.mode}",
                )

            self.mode = ctx.mode
            self.source_path = str(ctx.source_path) if ctx.source_path else None

            if ctx.mode == "live":
                data = await self.collect_live(ctx)
            else:
                if not ctx.source_path:
                    raise ValueError("source_path is required for path mode")
                data = await self.collect_path(ctx, ctx.source_path)

            self.results = data or {}

            return CollectorResult(
                schema_version="voxtrace.collector_result.v1",
                module=self.name,
                module_version=self.version,
                mode=ctx.mode,
                started_at=started_at,
                ended_at=utc_now_iso(),
                status="ok",
                data=data or {},
                error=None,
            )
        except Exception as e:
            return CollectorResult(
                schema_version="voxtrace.collector_result.v1",
                module=self.name,
                module_version=self.version,
                mode=ctx.mode,
                started_at=started_at,
                ended_at=utc_now_iso(),
                status="error",
                data={},
                error=str(e),
            )

    @abstractmethod
    async def collect_live(self, ctx: CollectorContext) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    async def collect_path(self, ctx: CollectorContext, root: Path) -> dict[str, Any]:
        raise NotImplementedError

    def collect(self):
        raise NotImplementedError("Use async collect_live/collect_path via the engine.")

    def parse(self):
        raise NotImplementedError("Use async collect_live/collect_path via the engine.")

