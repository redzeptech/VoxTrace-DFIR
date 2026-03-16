import argparse
import asyncio
import csv
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


VT_BASE = "https://www.virustotal.com/api/v3"

IPV4_RE = re.compile(
    r"(?<![\d.])"
    r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?![\d.])"
)
MD5_RE = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])")
SHA1_RE = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])")
SHA256_RE = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        addr.version == 4
        and not addr.is_private
        and not addr.is_loopback
        and not addr.is_link_local
        and not addr.is_multicast
        and not addr.is_reserved
    )


def extract_indicators(text: str, *, public_ips_only: bool = True) -> dict[str, set[str]]:
    ips = set(IPV4_RE.findall(text))
    if public_ips_only:
        ips = {ip for ip in ips if _is_public_ip(ip)}

    md5 = set(m.lower() for m in MD5_RE.findall(text))
    sha1 = set(s.lower() for s in SHA1_RE.findall(text))
    sha256 = set(s.lower() for s in SHA256_RE.findall(text))
    return {"ips": ips, "md5": md5, "sha1": sha1, "sha256": sha256}


async def _read_text(path: Path) -> str:
    try:
        return await asyncio.to_thread(path.read_text, encoding="utf-8", errors="ignore")
    except Exception:
        return ""


async def collect_indicators_from_paths(
    paths: Iterable[Path],
    *,
    include_exts: set[str],
    public_ips_only: bool,
    concurrency: int,
) -> tuple[dict[str, set[str]], dict[str, list[str]]]:
    sem = asyncio.Semaphore(max(1, concurrency))
    findings: dict[str, set[str]] = {"ips": set(), "md5": set(), "sha1": set(), "sha256": set()}
    sources: dict[str, list[str]] = {}

    async def handle_file(p: Path) -> None:
        if p.suffix.lower() not in include_exts:
            return
        async with sem:
            content = await _read_text(p)
        if not content:
            return
        inds = extract_indicators(content, public_ips_only=public_ips_only)
        for k, vals in inds.items():
            for v in vals:
                findings[k].add(v)
                sources.setdefault(v, []).append(str(p))

    await asyncio.gather(*(handle_file(p) for p in paths))
    return findings, sources


def iter_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    if not root.exists():
        return []
    out: list[Path] = []
    for p in root.rglob("*"):
        if p.is_file():
            out.append(p)
    return out


def _vt_request_json(url: str, api_key: str) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"x-apikey": api_key, "accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read()
    return json.loads(raw.decode("utf-8", errors="replace"))


@dataclass(frozen=True)
class VTResult:
    indicator: str
    kind: str  # "ip" | "file"
    malicious: int | None
    suspicious: int | None
    harmless: int | None
    undetected: int | None
    timeout: int | None
    raw: dict[str, Any] | None
    error: str | None


def _extract_stats(payload: dict[str, Any]) -> dict[str, int | None]:
    attrs = (payload.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    def gi(k: str) -> int | None:
        v = stats.get(k)
        return int(v) if isinstance(v, (int, float)) else None
    return {
        "malicious": gi("malicious"),
        "suspicious": gi("suspicious"),
        "harmless": gi("harmless"),
        "undetected": gi("undetected"),
        "timeout": gi("timeout"),
    }


async def vt_lookup(
    indicators: Iterable[tuple[str, str]],
    *,
    api_key: str,
    min_interval_seconds: float,
    concurrency: int,
    keep_raw: bool,
) -> list[VTResult]:
    sem = asyncio.Semaphore(max(1, concurrency))
    lock = asyncio.Lock()
    last_ts = 0.0

    async def throttled_request(url: str) -> dict[str, Any]:
        nonlocal last_ts
        async with lock:
            now = time.monotonic()
            wait = (last_ts + min_interval_seconds) - now
            if wait > 0:
                await asyncio.sleep(wait)
            last_ts = time.monotonic()
        return await asyncio.to_thread(_vt_request_json, url, api_key)

    async def one(ind: str, kind: str) -> VTResult:
        async with sem:
            try:
                if kind == "ip":
                    url = f"{VT_BASE}/ip_addresses/{ind}"
                elif kind == "file":
                    url = f"{VT_BASE}/files/{ind}"
                else:
                    return VTResult(ind, kind, None, None, None, None, None, None, f"unknown kind: {kind}")

                payload = await throttled_request(url)
                stats = _extract_stats(payload)
                return VTResult(
                    indicator=ind,
                    kind=kind,
                    malicious=stats["malicious"],
                    suspicious=stats["suspicious"],
                    harmless=stats["harmless"],
                    undetected=stats["undetected"],
                    timeout=stats["timeout"],
                    raw=payload if keep_raw else None,
                    error=None,
                )
            except urllib.error.HTTPError as e:
                try:
                    body = e.read().decode("utf-8", errors="replace")
                except Exception:
                    body = ""
                return VTResult(ind, kind, None, None, None, None, None, None, f"HTTP {e.code}: {body[:200]}")
            except Exception as e:
                return VTResult(ind, kind, None, None, None, None, None, None, str(e))

    return await asyncio.gather(*(one(ind, kind) for ind, kind in indicators))


def _as_file_indicators(md5: set[str], sha1: set[str], sha256: set[str]) -> set[str]:
    return set(md5) | set(sha1) | set(sha256)


async def main_async(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="VoxTrace Threat Intel (VirusTotal) - IP/hash lookup")
    ap.add_argument(
        "path",
        nargs="?",
        default="Outputs",
        help="Scan this file/folder for indicators (default: Outputs/)",
    )
    ap.add_argument("--out", default="", help="Write JSON results to this path (default: Logs/threat_intel_<ts>.json)")
    ap.add_argument(
        "--out-csv",
        default="",
        help="Write CSV results to this path (default: same as --out but .csv extension)",
    )
    ap.add_argument("--include-ext", default=".txt,.srt,.log,.json,.vtt,.tsv", help="Comma-separated extensions to scan")
    ap.add_argument("--public-ips-only", action="store_true", default=True, help="Only query public IPv4 (default: on)")
    ap.add_argument("--all-ips", action="store_true", help="Query private/reserved IPs too (overrides --public-ips-only)")
    ap.add_argument(
        "--vt-api-key",
        default=os.getenv("VT_API_KEY", ""),
        help="VirusTotal API key (or set VT_API_KEY env var)",
    )
    ap.add_argument(
        "--min-interval",
        type=float,
        default=float(os.getenv("VT_REQ_INTERVAL_SECONDS", "16")),
        help="Min seconds between VT requests (default: 16 ~ public API limit)",
    )
    ap.add_argument(
        "--concurrency",
        type=int,
        default=int(os.getenv("VOXTRACE_THREAT_INTEL_CONCURRENCY", "4")),
        help="Max concurrent lookups (default: 4)",
    )
    ap.add_argument(
        "--scan-concurrency",
        type=int,
        default=16,
        help="Max concurrent file reads while scanning (default: 16)",
    )
    ap.add_argument("--keep-raw", action="store_true", help="Include raw VT JSON per indicator in output")
    args = ap.parse_args(argv)

    root = Path(args.path)
    files = iter_files(root)
    if not files:
        print(f"[WARN] No files found under: {root}")
        return 0

    include_exts = {("." + e.lstrip(".")).lower() for e in str(args.include_ext).split(",") if e.strip()}
    public_ips_only = (not args.all_ips) and bool(args.public_ips_only)

    findings, sources = await collect_indicators_from_paths(
        files,
        include_exts=include_exts,
        public_ips_only=public_ips_only,
        concurrency=max(1, int(args.scan_concurrency)),
    )

    ips = sorted(findings["ips"])
    file_hashes = sorted(_as_file_indicators(findings["md5"], findings["sha1"], findings["sha256"]))

    print(f"[INFO] Indicators: ips={len(ips)} file_hashes={len(file_hashes)} (public_ips_only={public_ips_only})")

    if not args.vt_api_key:
        print("[WARN] VT API key not provided. Set VT_API_KEY env var or pass --vt-api-key.")
        print("[INFO] Extraction complete (no lookups performed).")
        return 2

    indicator_jobs: list[tuple[str, str]] = [(ip, "ip") for ip in ips] + [(h, "file") for h in file_hashes]
    results = await vt_lookup(
        indicator_jobs,
        api_key=args.vt_api_key,
        min_interval_seconds=max(0.0, float(args.min_interval)),
        concurrency=max(1, int(args.concurrency)),
        keep_raw=bool(args.keep_raw),
    )

    ts = time.strftime("%Y%m%d_%H%M%S")
    out_path = Path(args.out) if args.out else (Path("Logs") / f"threat_intel_{ts}.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_csv_path = Path(args.out_csv) if args.out_csv else out_path.with_suffix(".csv")

    payload = {
        "scanned_path": str(root),
        "include_exts": sorted(include_exts),
        "public_ips_only": public_ips_only,
        "indicators": {
            "ips": ips,
            "file_hashes": file_hashes,
        },
        "sources": sources,
        "results": [
            {
                "indicator": r.indicator,
                "kind": r.kind,
                "malicious": r.malicious,
                "suspicious": r.suspicious,
                "harmless": r.harmless,
                "undetected": r.undetected,
                "timeout": r.timeout,
                "error": r.error,
                "raw": r.raw,
            }
            for r in results
        ],
    }

    await asyncio.to_thread(out_path.write_text, json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    await asyncio.to_thread(_write_csv, out_csv_path, results, sources)
    print(f"[OK] Wrote: {out_path}")
    print(f"[OK] Wrote: {out_csv_path}")
    return 0


def _write_csv(out_path: Path, results: list[VTResult], sources: dict[str, list[str]]) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "indicator",
                "kind",
                "malicious",
                "suspicious",
                "harmless",
                "undetected",
                "timeout",
                "error",
                "sources",
            ],
        )
        w.writeheader()
        for r in results:
            srcs = sources.get(r.indicator, [])
            w.writerow(
                {
                    "indicator": r.indicator,
                    "kind": r.kind,
                    "malicious": r.malicious,
                    "suspicious": r.suspicious,
                    "harmless": r.harmless,
                    "undetected": r.undetected,
                    "timeout": r.timeout,
                    "error": r.error,
                    "sources": ";".join(srcs),
                }
            )


def main() -> None:
    raise SystemExit(asyncio.run(main_async(sys.argv[1:])))


if __name__ == "__main__":
    main()

