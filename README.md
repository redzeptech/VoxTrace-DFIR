# VoxTrace-DFIR v0.3.0

**Audio + System Artifact Forensics Framework for DFIR Investigations**

VoxTrace-DFIR started as a multilingual **audio/video evidence processing** toolkit.  
As of **v0.3.0**, it also provides a **Windows system artifact forensics** layer (EVTX/MFT + correlation), turning it into a hybrid DFIR framework that can support both **audio forensics** and **host artifact analysis** in one workflow.

---

## Why this exists / Neden var?

During investigations, analysts frequently encounter:

- Telegram voice messages
- WhatsApp audio notes
- Propaganda videos
- Foreign-language VoIP recordings
- Seized multimedia devices

However, investigators often do not speak the language contained in the evidence.

VoxTrace-DFIR allows analysts to **understand spoken content without knowing the language**.

In parallel, many cases require rapid **host triage** and **artifact-driven timelines**. v0.3.0 adds a modular collector engine to extract/parse key Windows artifacts and produce a unified run report.

---

## New Features (v0.3.0) / Yeni Özellikler

- **Hybrid Analysis (Live/Path)**: run collectors on the live host (`--live`) or against an offline triage folder (`--path`)
- **Advanced Artifact Parser (EVTX/MFT)**: event logs + MFT parsing for timeline-oriented analysis
- **Modular Plugin System**: drop-in collectors under `src/modules/` (dynamic discovery + per-module params)

---

## Core Capabilities / Temel Yetenekler

- Automatic audio extraction (FFmpeg)
- GPU-accelerated speech-to-text transcription (Whisper CUDA)
- Translation pipeline (TXT/SRT, timestamps preserved)
- Subtitle (SRT) translation with timestamps preserved
- Evidence processing logs
- Batch processing support
- Windows artifact analysis (EVTX/MFT) via plugin collectors
- Unified timeline builder (EVTX + MFT correlation)

---

## Workflow / İş Akışı (ASCII)

```text
                  ┌───────────────────────────────┐
                  │            Inputs/            │
                  │  Audio/Video Evidence Files   │
                  └───────────────┬───────────────┘
                                  │
                                  │
                 ┌────────────────▼────────────────┐
                 │        Media Pipeline            │
                 │  FFmpeg → Whisper → Translation  │
                 └────────────────┬────────────────┘
                                  │
                       Outputs/<case>/ (TXT/SRT/Logs)
                                  │
                                  │
                 ┌────────────────▼────────────────┐
                 │     Artifact Pipeline (v0.3.0)  │
                 │   --live or --path collectors   │
                 │  EVTX / MFT → Correlation → TL  │
                 └────────────────┬────────────────┘
                                  │
                          Logs/*.json + PDF report
```

---

## Output / Çıktılar

For each media file the tool generates:

- Original transcript (.txt)
- Translated transcript (.tr.txt)
- Original subtitles (.srt)
- Translated subtitles (.tr.srt)
- Processing logs
- Optional Threat Intel report (VirusTotal) for extracted IPs/hashes

For artifact analysis runs (v0.3.0 collector engine), the tool generates:

- A unified run report JSON (`Logs/voxtrace_run_<case>_<ts>.json`)
- Per-module artifacts under `Outputs/<case>_<ts>/modules/<module>/`
- Optional unified timeline (`timeline_builder`) in JSONL/CSV

---

## Requirements / Gereksinimler

- Windows 10 / 11
- Python 3.10+
- FFmpeg installed and in PATH
- Whisper installed
- NVIDIA GPU (recommended)
- `pip install -r requirements.txt`
- For legacy translation scripts (TXT/SRT): `pip install -r requirements-media.txt`

---

## Technical Stack / Teknik Altyapı

- **Media**:
  - FFmpeg for audio extraction/normalization
  - OpenAI Whisper for speech-to-text (CUDA supported)
  - Translation scripts (TXT/SRT) use `deep-translator` (see `requirements-media.txt`)
- **Artifact Analysis (v0.3.0)**:
  - **EVTX**: built-in collectors parse `.evtx` and can also use Windows-native `wevtutil` in live mode  
    - Optional high-performance **Rust-based EVTX engine**: `evtx_dump` (Rust) / `pyevtx-rs` bindings (if installed externally). This is compatible with the plugin design as an alternate backend.
  - **MFT**:
    - Offline parsing via MFT parsers (chunked + multiprocessing summarization)
    - Live acquisition options:
      - VSS-based copy (when preferred)
      - Low-level raw volume access (`\\.\C:`) to extract `$MFT` on Windows (Administrator required)

---

## Hybrid Collector Engine / Hibrit Collector Engine (Live Triage + Path Analysis)

VoxTrace-DFIR now includes a plugin-based collector engine under `src/`:

- **Live triage**: `python -m src.main --live`
- **Path analysis**: `python -m src.main --path <folder>`

### Usage / Kullanım (`--live` / `--path`)

```bash
# List discovered collectors
python -m src.main --live --list-modules

# Live triage run (writes unified JSON report)
python -m src.main --live --case mycase --out Logs\run.json --output-dir Outputs\triage_out

# Offline/path analysis run
python -m src.main --path C:\triage --case mycase --out Logs\run.json --output-dir Outputs\triage_out
```

Useful commands:

- List modules:
  - `python -m src.main --live --list-modules`
- Run selected modules:
  - `python -m src.main --live --modules system_info --out Logs\\run.json --output-dir Outputs\\triage_out`

Module parameters (advanced):

- Pass repeatable `--param module.key=value`
- Example (EVTX):
  - `python -m src.main --live --modules event_log_collector --param event_log_collector.channels=System,Application --param event_log_collector.limit=200 --param event_log_collector.inline_records=false --param event_log_collector.prefer_wevtutil=true`
  - Event ID filter example (Logon/Process Creation):
    - `python -m src.main --live --modules event_log_collector --param event_log_collector.channels=Security --param event_log_collector.event_ids=4624,4688 --param event_log_collector.prefer_wevtutil=true --param event_log_collector.inline_records=false`
    - Note: Security channel typically requires running the shell as Administrator; otherwise you may see \"access denied\".

Example (MFT):

- Path mode (copied `$MFT`):
  - `python -m src.main --path C:\\triage\\$MFT --modules mft_parser --param mft_parser.profile=quick --param mft_parser.timestomp_threshold_seconds=86400 --param mft_parser.write_csv=true`
- Live mode (VSS snapshot; Admin required):
  - `python -m src.main --live --modules mft_parser --param mft_parser.drive=C --param mft_parser.vss_cleanup=true`

Example (Unified Timeline):

- Run EVTX + MFT then build a merged timeline:
  - `python -m src.main --live --modules event_log_collector,mft_parser,timeline_builder --param event_log_collector.channels=Security --param event_log_collector.event_ids=4624,4688 --param event_log_collector.prefer_wevtutil=true --param event_log_collector.inline_records=false --param timeline_builder.window_seconds=300`

MFT speed tuning:

- Multiprocessing summary over batches (default 100,000 records per task):
  - `--param mft_parser.multiprocessing=true --param mft_parser.mp_records_per_task=100000 --param mft_parser.mp_workers=8 --param mft_parser.process_chunk_files_limit=0`

All module outputs are aggregated into a single JSON report with a stable schema.

## MFT Collector (Raw Disk) - Windows

`mft_collector` can extract `$MFT` via raw volume access (requires Administrator):

- Live:
  - `python -m src.main --live --modules mft_collector --param mft_collector.drive=C --param mft_collector.max_bytes=1073741824 --param mft_collector.format=csv`
- Path (already copied `$MFT`):
  - `python -m src.main --path C:\\triage\\$MFT --modules mft_collector --param mft_collector.format=csv`

---

## Media Processing (Legacy Runner) / Ses İşleme (Eski Runner)

1. Place evidence files inside `Inputs/`
2. Run:
   - `.\run.ps1` (PowerShell) veya `calistir.bat` (Batch)
3. Results appear in `Outputs/<filename>/`

### Güvenlik / Gizlilik Parametreleri (run.ps1)

| Parametre | Açıklama |
|-----------|----------|
| `-MaskSensitive` | Transcription çıktılarında telefon numarası ve e-posta adreslerini `***` ile maskeler |
| `-NoCleanup` | İşlem sonrası temp klasörlerini temizlemez (varsayılan: temizlenir) |

Örnek:
```powershell
.\run.ps1 -MaskSensitive
```

Otomatik uygulanan iyileştirmeler:
- **Dosya yolu maskeleme**: Log ve raporlarda `C:\Users\KullaniciAdi` → `C:\Users\[USER]`
- **Metadata temizliği**: TXT/SRT/VTT dosyalarının başı/sonundaki sistem bilgisi kaldırılır
- **Temp temizliği**: İşlem sonrası `temp_audio/` ve `%TEMP%\voxtrace_*` otomatik silinir

---

## Threat Intel (VirusTotal) - Optional

The `threat_intel.py` module scans generated outputs/logs to extract:

- IPv4 addresses
- File hashes (MD5/SHA1/SHA256)

Then it queries VirusTotal API v3 for quick reputation checks.

### Enable during processing

- Set environment variables:
  - `VOXTRACE_THREAT_INTEL=1`
  - `VT_API_KEY=<your_vt_api_key>`

The runner will create a JSON report under `Logs/` per processed file.

### Run manually

Example:

- Scan everything under `Outputs/`:
  - `python threat_intel.py Outputs`

- Scan one specific output folder and write report:
  - `python threat_intel.py Outputs\\some_file --out Logs\\threat_intel.json`

Notes:

- Public VirusTotal API is rate-limited; default request interval is ~16 seconds.
- You can tune it with `VT_REQ_INTERVAL_SECONDS` and `VOXTRACE_THREAT_INTEL_CONCURRENCY`.
- CSV output is generated alongside JSON by default (or use `--out-csv`).

---

## Reporting Engine (PDF) - Optional

The `reporting_engine.py` module generates a professional PDF report from:

- Output artifacts under `Outputs/<file>/`
- Optional Threat Intel JSON from `Logs/threat_intel_*.json`
- Optional run log `Logs/run_*.log`

### Enable during processing

- Set environment variable:
  - `VOXTRACE_REPORT=1`

If Threat Intel is also enabled, the PDF includes VirusTotal summary tables.

### Run manually

- Create a report for one output folder:
  - `python reporting_engine.py Outputs\\some_file --run-log Logs\\run_xxx.log --threat-intel-json Logs\\threat_intel_xxx.json --out Logs\\report.pdf`

## Important Notice

Do **NOT** upload actual evidence files to GitHub.

This repository intentionally ignores:

- Inputs/
- Outputs/
- Logs/
- media files

---

## Legal Disclaimer

This tool is provided for legitimate research, education, and lawful digital forensic investigations.  
The user is responsible for compliance with local laws and organizational policies.

---

## Author

Recep Şenel  
Independent DFIR & Windows Artifact Analyst
## Demonstration

### Processing
![Processing](docs/screenshot1.png)

### Generated Output
![Output](docs/screenshot2.png)
