import asyncio
import os
import sys
from pathlib import Path

from deep_translator import GoogleTranslator


def chunk_text(text: str, max_chars: int = 4500) -> list[str]:
    chunks: list[str] = []
    i, n = 0, len(text)
    while i < n:
        j = min(i + max_chars, n)
        if j < n:
            k = text.rfind(" ", i, j)
            if k > i + 100:
                j = k
        chunks.append(text[i:j])
        i = j
    return chunks


def log_line(log_path: str, msg: str) -> None:
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(msg + "\n")
    except PermissionError:
        alt = os.path.join(os.path.dirname(log_path), "translate_fallback.log")
        with open(alt, "a", encoding="utf-8") as f:
            f.write(msg + "\n")


def _translate_sync(text: str, src: str, tgt: str) -> str:
    # deep_translator / underlying HTTP is blocking; run in a worker thread.
    return GoogleTranslator(source=src, target=tgt).translate(text)


async def main_async() -> int:
    if len(sys.argv) < 6:
        print(
            "Kullanim: python translate_txt.py <input.txt> <source_lang> <target_lang> <outputs_dir> <log_path>"
        )
        return 1

    inp, src, tgt, out_dir, log_path = sys.argv[1:6]
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    inp_path = Path(inp)
    if not inp_path.exists():
        await asyncio.to_thread(log_line, log_path, f"HATA: Dosya bulunamadi: {inp}")
        return 1

    text = (await asyncio.to_thread(inp_path.read_text, encoding="utf-8")).strip()
    if not text:
        await asyncio.to_thread(log_line, log_path, f"UYARI: Bos dosya: {inp}")
        return 0

    concurrency = int(os.getenv("VOXTRACE_TRANSLATE_CONCURRENCY", "4"))
    concurrency = max(1, min(concurrency, 32))
    sem = asyncio.Semaphore(concurrency)
    log_lock = asyncio.Lock()

    async def alog(msg: str) -> None:
        async with log_lock:
            await asyncio.to_thread(log_line, log_path, msg)

    await alog(f"CEVIRI BASLADI: {inp_path.name} ({src}->{tgt}) (concurrency={concurrency})")

    chunks = chunk_text(text)
    out_parts: list[str] = [""] * len(chunks)
    cache: dict[str, str] = {}

    async def translate_one(idx0: int, ch: str) -> None:
        async with sem:
            if ch in cache:
                out_parts[idx0] = cache[ch]
                return
            try:
                out = await asyncio.to_thread(_translate_sync, ch, src, tgt)
            except Exception as e:
                await alog(f"HATA: Parca {idx0 + 1}: {e}")
                out = f"\n[CEVIRI HATASI - PARCA {idx0 + 1}] {e}\n{ch}\n"
            cache[ch] = out
            out_parts[idx0] = out

    await asyncio.gather(*(translate_one(i, ch) for i, ch in enumerate(chunks)))

    base = inp_path.stem
    out_path = Path(out_dir) / f"{base}.{tgt}.txt"
    await asyncio.to_thread(out_path.write_text, "\n\n".join(out_parts), encoding="utf-8")

    await alog(f"CEVIRI BITTI: {out_path}")
    print(f"Tamam: {out_path}")
    return 0


def main() -> None:
    raise SystemExit(asyncio.run(main_async()))


if __name__ == "__main__":
    main()