# VoxTrace-DFIR runner (PowerShell) - FINAL (stable paths + optional translation)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# --- Script root (single source of truth)
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

# --- PowerShell native-command stderr davranışını kapat (PS 7+)
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -Scope Global -ErrorAction SilentlyContinue) {
  $global:PSNativeCommandUseErrorActionPreference = $false
}

# --- Paths
$inDir   = Join-Path $root "Inputs"
$outDir  = Join-Path $root "Outputs"
$logDir  = Join-Path $root "Logs"
$doneDir = Join-Path $inDir "Done"
New-Item -ItemType Directory -Force -Path $inDir, $outDir, $logDir, $doneDir | Out-Null

# --- Run log
$ts  = Get-Date -Format "yyyyMMdd_HHmmss"
$log = Join-Path $logDir "run_$ts.log"

function Log([string]$msg) {
  $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg
  Add-Content -Path $log -Value $line -Encoding utf8
  Write-Host $line
}

function Ensure-Command([string]$name) {
  if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
    Log "ERROR: '$name' not found in PATH. Fix PATH or provide full path."
    exit 1
  }
}

Log "Start"
Log "ROOT=$root"
Log "IN=$inDir"
Log "OUT=$outDir"
Log "LOG=$log"

# --- Required commands
Ensure-Command "ffmpeg"
Ensure-Command "whisper"
Ensure-Command "python"

# --- Language settings
# NOTE: translate_txt.py / translate_srt.py supports src/tgt; set src='auto' if you want autodetect.
$srcLang     = "auto"
$tgtLang     = "tr"

# Whisper language:
# - If you pass --language, Whisper may force that language.
# - Using "English" is OK for EN-only audio; for mixed audio consider removing --language.
$whisperLang = "English"

# --- Collect input files
$files = Get-ChildItem $inDir -File | Where-Object {
  $_.Name -match '\.(wav|mp3|m4a|mp4|mkv|mov|webm)$'
}

if (-not $files) {
  Log "No input files found."
  exit 0
}

foreach ($f in $files) {
  Log "=============================="
  Log "File=$($f.Name)"

  $base    = [IO.Path]::GetFileNameWithoutExtension($f.Name)
  $thisOut = Join-Path $outDir $base
  New-Item -ItemType Directory -Force -Path $thisOut | Out-Null

  $mp3 = Join-Path $thisOut "$base.mp3"
  $txt = Join-Path $thisOut "$base.txt"
  $srt = Join-Path $thisOut "$base.srt"

  # --------------------------
  Log "[1/4] Audio prep"
  if ($f.Extension -ieq ".mp3") {
    Copy-Item -Force $f.FullName $mp3
    Log "Audio already mp3 -> copied"
  } else {
    # ffmpeg stderr'e progress basar; bunu hata gibi görme
    $PSNativeCommandUseErrorActionPreference = $false
    $ErrorActionPreference = "Continue"

    & ffmpeg -y -i $f.FullName -vn -acodec mp3 -ab 128k $mp3 2>&1 |
      Out-File -FilePath $log -Append -Encoding utf8

    if ($LASTEXITCODE -ne 0) {
      Log "ERROR: ffmpeg failed with exit code $LASTEXITCODE"
      continue
    }
    Log "ffmpeg OK -> $mp3"
  }

  # --------------------------
  Log "[2/4] Whisper transcribe (CUDA)"
  & whisper $mp3 --model medium --device cuda --task transcribe --language $whisperLang --output_format all --output_dir $thisOut 2>&1 |
    Out-File -FilePath $log -Append -Encoding utf8

  if ($LASTEXITCODE -ne 0) {
    Log "ERROR: whisper failed with exit code $LASTEXITCODE"
    continue
  }
  Log "whisper OK -> outputs in $thisOut"

  # --------------------------
  # [3/4] TXT translate (optional, non-blocking)
  Log "[3/4] TXT translate"
  $translateTxtPy  = Join-Path $root "translate_txt.py"
  $translateTxtLog = Join-Path $logDir ("translate_txt_{0}_{1}.log" -f $base, $ts)

  Log ("[DEBUG] translateTxtPy={0} exists={1}" -f $translateTxtPy, (Test-Path $translateTxtPy))
  Log ("[DEBUG] txt={0} exists={1}" -f $txt, (Test-Path $txt))

  if ((Test-Path $translateTxtPy) -and (Test-Path $txt)) {
    & python $translateTxtPy $txt $srcLang $tgtLang $thisOut $translateTxtLog

    if ($LASTEXITCODE -ne 0) {
      Log "[WARN] translate_txt.py failed (exit=$LASTEXITCODE). See: $translateTxtLog"
    } else {
      Log "[INFO] TXT translate OK"
    }
  } else {
    Log "[WARN] TXT translate skipped (missing script or txt file)."
  }

  # --------------------------
  # [4/4] SRT translate (optional, non-blocking)
  Log "[4/4] SRT translate"
  $translateSrtPy  = Join-Path $root "translate_srt.py"
  $translateSrtLog = Join-Path $logDir ("translate_srt_{0}_{1}.log" -f $base, $ts)

  Log ("[DEBUG] translateSrtPy={0} exists={1}" -f $translateSrtPy, (Test-Path $translateSrtPy))
  Log ("[DEBUG] srt={0} exists={1}" -f $srt, (Test-Path $srt))

  if ((Test-Path $translateSrtPy) -and (Test-Path $srt)) {
    & python $translateSrtPy $srt $srcLang $tgtLang $thisOut $translateSrtLog

    if ($LASTEXITCODE -ne 0) {
      Log "[WARN] translate_srt.py failed (exit=$LASTEXITCODE). See: $translateSrtLog"
    } else {
      Log ("[INFO] SRT translate OK -> {0}" -f (Join-Path $thisOut ($base + ".tr.srt")))
    }
  } else {
    Log "[WARN] SRT translate skipped (missing script or srt file)."
  }

  # --------------------------
  # Successful processing -> move to Done
  Move-Item -Force $f.FullName $doneDir
  Log "OK Done -> $thisOut"
}

Log "Finished"