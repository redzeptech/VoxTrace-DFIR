import asyncio
import os
import re
import sys
from pathlib import Path

from deep_translator import GoogleTranslator


TIME_RE = re.compile(r"^\d{2}:\d{2}:\d{2},\d{3} --> \d{2}:\d{2}:\d{2},\d{3}$")


def log_line(log_path: str, msg: str) -> None:
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(msg + "\n")
    except PermissionError:
        alt = os.path.join(os.path.dirname(log_path), "translate_fallback.log")
        with open(alt, "a", encoding="utf-8") as f:
            f.write(msg + "\n")


def _translate_sync(text: str, src: str, tgt: str) -> str:
    return GoogleTranslator(source=src, target=tgt).translate(text)


async def main_async() -> int:
    if len(sys.argv) < 6:
        print("Kullanim: python translate_srt.py <input.srt> <source_lang> <target_lang> <outputs_dir> <log_path>")
        return 1

    inp, src, tgt, out_dir, log_path = sys.argv[1:6]
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    inp_path = Path(inp)
    if not inp_path.exists():
        await asyncio.to_thread(log_line, log_path, f"HATA: SRT bulunamadi: {inp}")
        return 1

    concurrency = int(os.getenv("VOXTRACE_TRANSLATE_CONCURRENCY", "4"))
    concurrency = max(1, min(concurrency, 32))
    sem = asyncio.Semaphore(concurrency)
    log_lock = asyncio.Lock()

    async def alog(msg: str) -> None:
        async with log_lock:
            await asyncio.to_thread(log_line, log_path, msg)

    lines = (await asyncio.to_thread(inp_path.read_text, encoding="utf-8")).splitlines()
    await alog(f"SRT CEVIRI BASLADI: {inp_path.name} ({src}->{tgt}) (concurrency={concurrency})")

    # SRT parsing: Whisper genelde düzgün SRT üretir.
    # Blok bazlı çeviri ile (index+time + N text line + blank) tek çağrıda çevrilir.
    segments: list[tuple[str, object]] = []
    i = 0
    while i < len(lines):
        s = lines[i].strip()
        if s.isdigit() and i + 1 < len(lines) and TIME_RE.match(lines[i + 1].strip()):
            idx_line = lines[i]
            time_line = lines[i + 1]
            i += 2
            text_lines: list[str] = []
            while i < len(lines) and lines[i].strip() != "":
                text_lines.append(lines[i])
                i += 1
            # consume blank line if present (keep at least one blank to preserve SRT block separation)
            if i < len(lines) and lines[i].strip() == "":
                i += 1
            segments.append(("block", (idx_line, time_line, text_lines)))
            continue

        segments.append(("raw", lines[i]))
        i += 1

    cache: dict[str, str] = {}
    out_parts: list[str] = []
    jobs: list[asyncio.Task[str]] = []
    placeholders: list[int] = []
    placeholder_texts: list[str] = []

    def should_translate_raw(line: str) -> bool:
        st = line.strip()
        if not st:
            return False
        if st.isdigit() or TIME_RE.match(st):
            return False
        return True

    async def translate_text(text: str) -> str:
        if text in cache:
            return cache[text]
        async with sem:
            try:
                out = await asyncio.to_thread(_translate_sync, text, src, tgt)
            except Exception as e:
                await alog(f"HATA: SRT ceviri: {e} | {text[:80]}")
                out = text
            cache[text] = out
            return out

    for kind, payload in segments:
        if kind == "block":
            idx_line, time_line, text_lines = payload  # type: ignore[misc]
            out_parts.append(idx_line)
            out_parts.append(time_line)
            joined = "\n".join(t.strip() for t in text_lines).strip()
            if joined:
                placeholders.append(len(out_parts))
                placeholder_texts.append(joined)
                out_parts.append("")  # placeholder
            else:
                out_parts.append("")
            out_parts.append("")  # blank line between blocks
        else:
            raw = payload  # type: ignore[assignment]
            if should_translate_raw(raw):
                placeholders.append(len(out_parts))
                placeholder_texts.append(raw.strip())
                out_parts.append("")  # placeholder
            else:
                out_parts.append(raw)

    jobs = [asyncio.create_task(translate_text(t)) for t in placeholder_texts]
    if jobs:
        results = await asyncio.gather(*jobs)
        for pos, translated in zip(placeholders, results, strict=True):
            out_parts[pos] = translated

    base = inp_path.stem
    out_path = Path(out_dir) / f"{base}.{tgt}.srt"
    await asyncio.to_thread(out_path.write_text, "\n".join(out_parts), encoding="utf-8")

    await alog(f"SRT CEVIRI BITTI: {out_path}")
    print(f"Tamam: {out_path}")
    return 0


def main() -> None:
    raise SystemExit(asyncio.run(main_async()))


if __name__ == "__main__":
    main()