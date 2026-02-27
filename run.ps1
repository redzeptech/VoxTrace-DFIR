# VoxTrace-DFIR runner (PowerShell) - CLEAN FULL VERSION

Set-StrictMode -Version Latest

# --- PowerShell native-command stderr davranışını kapat (PS 7+)
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -Scope Global -ErrorAction SilentlyContinue) {
  $global:PSNativeCommandUseErrorActionPreference = $false
}

# Hataları "native stderr = error" gibi yorumlayıp akışı bozmayalım
$ErrorActionPreference = "Continue"

$root    = Split-Path -Parent $MyInvocation.MyCommand.Path
$inDir   = Join-Path $root "Inputs"
$outDir  = Join-Path $root "Outputs"
$logDir  = Join-Path $root "Logs"
$doneDir = Join-Path $inDir "Done"

New-Item -ItemType Directory -Force -Path $inDir, $outDir, $logDir, $doneDir | Out-Null

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

# --- Gereken komutlar var mı?
Ensure-Command "ffmpeg"
Ensure-Command "whisper"
Ensure-Command "python"

# --- Dil ayarları
# Demo: English -> Turkish. Arapça için sonra ar/tr yaparsın.
$srcLang     = "en"
$tgtLang     = "tr"
$whisperLang = "English"

# --- Input dosyalarını topla
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
  Log "[3/4] TXT translate"
  if (Test-Path $txt) {
    & python (Join-Path $root "translate_txt.py") $txt $srcLang $tgtLang $thisOut $log 2>&1 |
      Out-File -FilePath $log -Append -Encoding utf8

    if ($LASTEXITCODE -ne 0) {
      Log "ERROR: translate_txt.py failed with exit code $LASTEXITCODE"
      continue
    }
  } else {
    Log "WARN: TXT missing: $txt"
  }

  # --------------------------
  Log "[4/4] SRT translate"
  if (Test-Path $srt) {
    & python (Join-Path $root "translate_srt.py") $srt $srcLang $tgtLang $thisOut $log 2>&1 |
      Out-File -FilePath $log -Append -Encoding utf8

    if ($LASTEXITCODE -ne 0) {
      Log "ERROR: translate_srt.py failed with exit code $LASTEXITCODE"
      continue
    }
  } else {
    Log "WARN: SRT missing: $srt"
  }

  # --------------------------
  # Başarılıysa dosyayı Done'a taşı
  Move-Item -Force $f.FullName $doneDir
  Log "OK Done -> $thisOut"
}

Log "Finished"