import sys, os
from datetime import datetime
from deep_translator import GoogleTranslator

def chunk_text(text: str, max_chars: int = 4500):
    chunks = []
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

import os

import os

def log_line(log_path: str, msg: str):
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(msg + "\n")
    except PermissionError:
        alt = os.path.join(os.path.dirname(log_path), "translate_fallback.log")
        with open(alt, "a", encoding="utf-8") as f:
            f.write(msg + "\n")
def main():
    if len(sys.argv) < 6:
        print("Kullanim: python translate_txt.py <input.txt> <source_lang> <target_lang> <outputs_dir> <log_path>")
        sys.exit(1)

    inp, src, tgt, out_dir, log_path = sys.argv[1:6]
    os.makedirs(out_dir, exist_ok=True)

    if not os.path.exists(inp):
        log_line(log_path, f"HATA: Dosya bulunamadi: {inp}")
        sys.exit(1)

    with open(inp, "r", encoding="utf-8") as f:
        text = f.read().strip()

    if not text:
        log_line(log_path, f"UYARI: Bos dosya: {inp}")
        sys.exit(0)

    translator = GoogleTranslator(source=src, target=tgt)

    log_line(log_path, f"CEVIRI BASLADI: {os.path.basename(inp)} ({src}->{tgt})")
    out_parts = []
    for idx, ch in enumerate(chunk_text(text), 1):
        try:
            out = translator.translate(ch)
        except Exception as e:
            log_line(log_path, f"HATA: Parca {idx}: {e}")
            out = f"\n[CEVIRI HATASI - PARCA {idx}] {e}\n{ch}\n"
        out_parts.append(out)

    base = os.path.splitext(os.path.basename(inp))[0]
    out_path = os.path.join(out_dir, f"{base}.{tgt}.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n\n".join(out_parts))

    log_line(log_path, f"CEVIRI BITTI: {out_path}")
    print(f"Tamam: {out_path}")

if __name__ == "__main__":
    main()