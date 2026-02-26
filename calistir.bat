@echo off
setlocal enabledelayedexpansion
cd /d %~dp0

set IN=%~dp0Inputs
set OUT=%~dp0Outputs
set LOGDIR=%~dp0Logs
set DONE=%IN%\Done
if not exist "%DONE%" mkdir "%DONE%"

if not exist "%IN%" mkdir "%IN%"
if not exist "%OUT%" mkdir "%OUT%"
if not exist "%LOGDIR%" mkdir "%LOGDIR%"

set TS=%DATE:~-4%%DATE:~3,2%%DATE:~0,2%_%TIME:~0,2%%TIME:~3,2%%TIME:~6,2%
set TS=%TS: =0%
set LOG=%LOGDIR%\run_%TS%.log

echo [INFO] Basladi > "%LOG%"
echo [INFO] Input: "%IN%" >> "%LOG%"
echo [INFO] Output: "%OUT%" >> "%LOG%"

pushd "%IN%"

for %%f in (*.mp4 *.mkv *.mov *.webm *.m4a *.mp3 *.wav) do (
for %%f in (*.mp4 *.mkv *.mov *.webm *.m4a *.mp3 *.wav) do (
    echo ============================== >> "%LOG%"
    echo [INFO] Dosya: %%f >> "%LOG%"

    set BASE=%%~nf
    set OUTDIR=%OUT%\!BASE!

    if not exist "!OUTDIR!" mkdir "!OUTDIR!"

    set MP3=!OUTDIR!\!BASE!.mp3
    set TXT=!OUTDIR!\!BASE!.txt
    set SRT=!OUTDIR!\!BASE!.srt

    echo [1/4] Ses hazirlaniyor... >> "%LOG%"
    if /I "%%~xf"==".mp3" (
        copy /y "%%f" "!MP3!" >nul
    ) else (
        ffmpeg -y -i "%%f" -vn -acodec mp3 -ab 128k "!MP3!" >> "%LOG%" 2>&1
    )

    echo [2/4] Whisper (CUDA) transcribe... >> "%LOG%"
    whisper "!MP3!" --model medium --device cuda --task transcribe --language Arabic --output_dir "!OUTDIR!" >> "%LOG%" 2>&1

    echo [3/4] TXT -> Turkce... >> "%LOG%"
    if exist "!TXT!" (
        python "%~dp0translate_txt.py" "!TXT!" ar tr "!OUTDIR!" "%LOG%" >> "%LOG%" 2>&1
    ) else (
        echo [WARN] TXT bulunamadi, ceviri atlandi: !TXT! >> "%LOG%"
    )

    echo [4/4] SRT -> Turkce... >> "%LOG%"
    if exist "!SRT!" (
        python "%~dp0translate_srt.py" "!SRT!" ar tr "!OUTDIR!" "%LOG%" >> "%LOG%" 2>&1
    ) else (
        echo [WARN] SRT bulunamadi, SRT ceviri atlandi: !SRT! >> "%LOG%"
    )

    echo [OK] Tamamlandi: %%f -> !OUTDIR! >> "%LOG%"
	move /y "%%f" "%DONE%" >nul
)

popd
echo. >> "%LOG%"
echo [DONE] Islem tamamlandi. >> "%LOG%"

echo ISLEM TAMAMLANDI
echo Log: %LOG%
pause