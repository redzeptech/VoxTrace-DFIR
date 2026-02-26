@echo off
setlocal EnableExtensions
cd /d "%~dp0"

chcp 65001 >nul

REM ==== Ayarlar ====
set "SRC_LANG=en"
set "TGT_LANG=tr"
set "WHISPER_LANG=English"
set "WHISPER_MODEL=medium"
set "WHISPER_DEVICE=cuda"

set "IN=%~dp0Inputs"
set "OUT=%~dp0Outputs"
set "LOGDIR=%~dp0Logs"
set "DONE=%IN%\Done"

if not exist "%IN%" mkdir "%IN%"
if not exist "%OUT%" mkdir "%OUT%"
if not exist "%LOGDIR%" mkdir "%LOGDIR%"
if not exist "%DONE%" mkdir "%DONE%"

set "TS=%DATE:~-4%%DATE:~3,2%%DATE:~0,2%_%TIME:~0,2%%TIME:~3,2%%TIME:~6,2%"
set "TS=%TS: =0%"
set "LOG=%LOGDIR%\run_%TS%.log"

> "%LOG%" (
  echo [INFO] Basladi
  echo [INFO] Input: "%IN%"
  echo [INFO] Output: "%OUT%"
  echo [INFO] Lang: %SRC_LANG% -> %TGT_LANG% (whisper=%WHISPER_LANG%)
  echo.
)

pushd "%IN%" || (echo [ERROR] Inputs klasorune girilemedi>>"%LOG%" & goto :END)

setlocal EnableDelayedExpansion
set /a N=0

for %%f in (*.mp4 *.mkv *.mov *.webm *.m4a *.mp3 *.wav) do (
  set /a N+=1
  call :PROCESS "%%f" !N!
)

endlocal
popd

:END
>> "%LOG%" (
  echo.
  echo [DONE] Islem tamamlandi.
)

echo ISLEM TAMAMLANDI
echo Log: %LOG%
pause
exit /b 0


:PROCESS
setlocal EnableDelayedExpansion
set "FILE=%~1"
set "IDX=%~2"

>> "%LOG%" (
  echo ==============================
  echo [INFO] Dosya: !FILE!
)

set "BASE=file_!IDX!"
set "OUTDIR=%OUT%\!BASE!"
if not exist "!OUTDIR!" mkdir "!OUTDIR!"

set "MP3=!OUTDIR!\!BASE!.mp3"
set "TXT=!OUTDIR!\!BASE!.txt"
set "SRT=!OUTDIR!\!BASE!.srt"

>> "%LOG%" echo [DEBUG] A1: ffmpeg/copy basliyor

if /I "%~x1"==".mp3" (
  copy /y "!FILE!" "!MP3!" >nul
  set "RC=!errorlevel!"
  >> "%LOG%" echo [DEBUG] copy RC=!RC!
  if not "!RC!"=="0" (
    >> "%LOG%" echo [ERROR] MP3 kopyalama basarisiz
    endlocal & goto :eof
  )
) else (
  ffmpeg -y -i "!FILE!" -vn -acodec mp3 -ab 128k "!MP3!" >> "%LOG%" 2>&1
  set "RC=!errorlevel!"
  >> "%LOG%" echo [DEBUG] ffmpeg RC=!RC!
  if not "!RC!"=="0" (
    >> "%LOG%" echo [ERROR] ffmpeg basarisiz
    endlocal & goto :eof
  )
)

>> "%LOG%" echo [DEBUG] A2: ffmpeg bitti, Whisper'a geciyorum

>> "%LOG%" echo [2/4] Whisper (!WHISPER_DEVICE!) transcribe...
whisper "!MP3!" --model %WHISPER_MODEL% --device %WHISPER_DEVICE% --task transcribe --language %WHISPER_LANG% --output_format all --output_dir "!OUTDIR!" >> "%LOG%" 2>&1
set "RC=!errorlevel!"
>> "%LOG%" echo [DEBUG] whisper RC=!RC!
if not "!RC!"=="0" (
  >> "%LOG%" echo [ERROR] whisper basarisiz
  endlocal & goto :eof
)

>> "%LOG%" echo [DEBUG] A3: Whisper bitti, ceviriye geciyorum

>> "%LOG%" echo [3/4] TXT -> %TGT_LANG%...
if exist "!TXT!" (
  python "%~dp0translate_txt.py" "!TXT!" %SRC_LANG% %TGT_LANG% "!OUTDIR!" "%LOG%" >> "%LOG%" 2>&1
  set "RC=!errorlevel!"
  >> "%LOG%" echo [DEBUG] translate_txt RC=!RC!
) else (
  >> "%LOG%" echo [WARN] TXT yok: !TXT!
)

>> "%LOG%" echo [4/4] SRT -> %TGT_LANG%...
if exist "!SRT!" (
  python "%~dp0translate_srt.py" "!SRT!" %SRC_LANG% %TGT_LANG% "!OUTDIR!" "%LOG%" >> "%LOG%" 2>&1
  set "RC=!errorlevel!"
  >> "%LOG%" echo [DEBUG] translate_srt RC=!RC!
) else (
  >> "%LOG%" echo [WARN] SRT yok: !SRT!
)

>> "%LOG%" echo [OK] Tamamlandi: !FILE! -> !OUTDIR!
move /y "!FILE!" "%DONE%" >nul

endlocal & goto :eof