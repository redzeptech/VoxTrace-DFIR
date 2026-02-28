Tested on Windows 11 + Python 3.10 + CUDA Whisper
Keywords: DFIR, Digital Forensics, Audio Forensics, Whisper, Evidence Processing, Incident Response
✔ Pipeline execution verified with Stage4 completion marker (_STAGE4_OK.txt).
# VoxTrace-DFIR

**Multilingual Audio Evidence Processing Toolkit for DFIR Investigations**

VoxTrace-DFIR is a lightweight automation tool designed to help digital forensic and incident response (DFIR) analysts process audio and video evidence containing foreign language speech.

The tool automatically extracts audio, transcribes speech using OpenAI Whisper (CUDA supported), and translates the content while preserving subtitle timing.

---

## Why this exists

During investigations, analysts frequently encounter:

- Telegram voice messages
- WhatsApp audio notes
- Propaganda videos
- Foreign-language VoIP recordings
- Seized multimedia devices

However, investigators often do not speak the language contained in the evidence.

VoxTrace-DFIR allows analysts to **understand spoken content without knowing the language**.

---

## Features

- Automatic audio extraction (FFmpeg)
- GPU-accelerated speech-to-text transcription (Whisper CUDA)
- Arabic → Turkish translation
- Subtitle (SRT) translation with timestamps preserved
- Evidence processing logs
- Batch processing support

---

## Workflow
Video / Audio Evidence
↓
Audio Extraction
↓
Speech Transcription (Whisper)
↓
Translation
↓
Readable Text + Subtitles
---

## Output

For each media file the tool generates:

- Original transcript (.txt)
- Translated transcript (.tr.txt)
- Original subtitles (.srt)
- Translated subtitles (.tr.srt)
- Processing logs

---

## Requirements

- Windows 10 / 11
- Python 3.10+
- FFmpeg installed and in PATH
- Whisper installed
- NVIDIA GPU (recommended)
- `pip install deep-translator`

---

## Usage

1. Place evidence files inside `Inputs/`
2. Run:
tools\calistir.bat

3. Results appear in `Outputs/<filename>/`

---

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
VoxTrace is designed as a forensic helper tool, not a media utility.

Evidence extraction must never stop due to auxiliary module failures
(e.g., translation, subtitle formatting or external API problems).

Core artifacts (txt, srt, json) are always generated even if optional
processing stages fail. This behavior is intentional.
## Author

Recep Şenel  
Independent DFIR & Windows Artifact Analyst
## Demonstration

### Processing
![Processing](docs/screenshot1.png)

### Generated Output
![Output](docs/screenshot2.png)
