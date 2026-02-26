# VoxTrace-DFIR

Automatic extraction, transcription and translation of audio/video evidence for DFIR investigations.

## What it does
- Extracts audio from video (FFmpeg)
- Transcribes speech to text (Whisper + CUDA)
- Translates Arabic -> Turkish (TXT + SRT) while preserving SRT timestamps
- Writes per-run logs for traceability

## Requirements
- Windows 10/11
- Python 3.10+
- FFmpeg in PATH
- NVIDIA GPU + CUDA-enabled PyTorch (recommended)
- `pip install deep-translator`
- Whisper installed

## Usage
1. Put your media files into `Inputs\`
2. Run `tools\calistir.bat`
3. Results will be in `Outputs\<filename>\`
   - `<name>.txt` (original)
   - `<name>.tr.txt` (Turkish)
   - `<name>.srt` (original subtitles)
   - `<name>.tr.srt` (Turkish subtitles)
4. Logs are stored in `Logs\`

## Notes
- Translation uses an online translator (requires internet).
- Do not upload evidence files to GitHub. This repository intentionally ignores Inputs/Outputs/Logs and media files.

## Disclaimer
This tool is intended for lawful DFIR / incident response / research use. You are responsible for compliance with local laws and policies.
