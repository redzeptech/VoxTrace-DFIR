from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from src.core.base_collector import CollectorContext, PluginCollector


class AudioForensics(PluginCollector):
    """
    Audio evidence processing via Whisper (Python).

    Output: segment-based, time-stamped events suitable for timeline correlation.
    """

    name = "audio_forensics"
    version = "0.1.0"
    description = "Transcribe audio/video via Whisper and emit timestamped speech segments."

    supports_live = False
    supports_path = True

    def collect(self):
        return str(getattr(self, "source_path", "") or "")

    def parse(self):
        src = self.collect()
        if not src:
            self.results = {"error": "source_path is required (media file path)."}
            return self.results

        media_path = Path(src)
        if not media_path.exists() or not media_path.is_file():
            self.results = {"error": f"media file not found: {media_path}"}
            return self.results

        # Lazy import so the rest of the framework can run without Whisper installed.
        try:
            import whisper  # type: ignore
        except Exception as e:
            self.results = {
                "error": "Whisper Python package not installed. Install with: pip install openai-whisper",
                "details": str(e),
            }
            return self.results

        model_name = "base"
        device = None
        language = None

        try:
            model_name = str(getattr(self, "_model_name", "") or "base")
        except Exception:
            model_name = "base"

        model = whisper.load_model(model_name, device=device)
        result = model.transcribe(str(media_path), language=language)

        findings: list[dict[str, Any]] = []
        for seg in result.get("segments") or []:
            try:
                findings.append(
                    {
                        "timestamp_start": float(seg.get("start", 0.0)),
                        "timestamp_end": float(seg.get("end", 0.0)),
                        "text": str(seg.get("text", "")).strip(),
                        "event_type": "AUDIO_SPEECH",
                    }
                )
            except Exception:
                continue

        self.results = {
            "source_media": str(media_path),
            "model": model_name,
            "segments_count": len(findings),
            "segments": findings,
        }
        return self.results

    async def collect_live(self, ctx: CollectorContext) -> dict[str, Any]:
        return {"error": "audio_forensics supports only --path mode (provide a media file path)."}

    async def collect_path(self, ctx: CollectorContext, root: Path) -> dict[str, Any]:
        # In path mode, use ctx.source_path as media file (root arg is the same path from engine).
        self._model_name = ctx.get_param(self.name, "model", "base") or "base"
        mod_dir = ctx.ensure_module_dir(self.name)

        data = await asyncio.to_thread(self.parse)
        if isinstance(data, dict) and "segments" in data:
            segments = data.get("segments") or []
            out_json = mod_dir / "audio_segments.json"
            out_jsonl = mod_dir / "audio_segments.jsonl"
            out_txt = mod_dir / "transcript.txt"

            await asyncio.to_thread(out_json.write_text, json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            await asyncio.to_thread(
                out_jsonl.write_text,
                "\n".join(json.dumps(x, ensure_ascii=False) for x in segments if isinstance(x, dict)),
                encoding="utf-8",
            )
            await asyncio.to_thread(
                out_txt.write_text,
                "\n".join(str(x.get("text") or "") for x in segments if isinstance(x, dict)),
                encoding="utf-8",
            )
            data["artifacts"] = {
                "audio_segments_json": str(out_json),
                "audio_segments_jsonl": str(out_jsonl),
                "transcript_txt": str(out_txt),
            }
        return data if isinstance(data, dict) else {"error": "unexpected audio_forensics output"}


def get_collector() -> PluginCollector:
    return AudioForensics()

