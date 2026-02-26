import sys, os, re
from datetime import datetime
from deep_translator import GoogleTranslator

TIME_RE = re.compile(r"^\d{2}:\d{2}:\d{2},\d{3} --> \d{2}:\d{2}:\d{2},\d{3}$")

def log_line(log_path: str, msg: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(f"[{ts}] {msg}\n")

def main():
    if len(sys.argv) < 6:
        print("Kullanim: python translate_srt.py <input.srt> <source_lang> <target_lang> <outputs_dir> <log_path>")
        sys.exit(1)

    inp, src, tgt, out_dir, log_path = sys.argv[1:6]
    os.makedirs(out_dir, exist_ok=True)

    if not os.path.exists(inp):
        log_line(log_path, f"HATA: SRT bulunamadi: {inp}")
        sys.exit(1)

    translator = GoogleTranslator(source=src, target=tgt)

    with open(inp, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    log_line(log_path, f"SRT CEVIRI BASLADI: {os.path.basename(inp)} ({src}->{tgt})")

    out_lines = []
    for line in lines:
        s = line.strip()
        if not s:
            out_lines.append("")
            continue
        if s.isdigit() or TIME_RE.match(s):
            out_lines.append(line)
            continue
        # metin satırı -> çevir
        try:
            out_lines.append(translator.translate(s))
        except Exception as e:
            log_line(log_path, f"HATA: SRT satiri: {e} | {s[:80]}")
            out_lines.append(s)

    base = os.path.splitext(os.path.basename(inp))[0]
    out_path = os.path.join(out_dir, f"{base}.{tgt}.srt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(out_lines))

    log_line(log_path, f"SRT CEVIRI BITTI: {out_path}")
    print(f"Tamam: {out_path}")

if __name__ == "__main__":
    main()