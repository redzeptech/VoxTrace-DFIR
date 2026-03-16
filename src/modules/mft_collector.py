from __future__ import annotations

import asyncio
import os
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.core.base_collector import BaseCollector, CollectorContext


NTFS_OEM_ID = b"NTFS    "
ATTR_TYPE_DATA = 0x80
ATTR_TYPE_END = 0xFFFFFFFF


@dataclass(frozen=True)
class NtfsBoot:
    bytes_per_sector: int
    sectors_per_cluster: int
    cluster_size: int
    mft_lcn: int
    file_record_size: int


def _le_u16(b: bytes, off: int) -> int:
    return int.from_bytes(b[off : off + 2], "little", signed=False)


def _le_u32(b: bytes, off: int) -> int:
    return int.from_bytes(b[off : off + 4], "little", signed=False)


def _le_i8(b: bytes, off: int) -> int:
    return int.from_bytes(b[off : off + 1], "little", signed=True)


def _le_i64(b: bytes, off: int) -> int:
    return int.from_bytes(b[off : off + 8], "little", signed=True)


def _parse_ntfs_bootsector(bs: bytes) -> NtfsBoot:
    if len(bs) < 90:
        raise ValueError("boot sector too small")
    if bs[3:11] != NTFS_OEM_ID:
        raise ValueError("not an NTFS volume (OEM ID mismatch)")
    bps = _le_u16(bs, 11)
    spc = bs[13]
    if bps <= 0 or spc <= 0:
        raise ValueError("invalid NTFS geometry")
    cluster_size = bps * spc
    mft_lcn = _le_i64(bs, 48)
    cpr = _le_i8(bs, 64)
    if cpr < 0:
        fr_size = 1 << (-cpr)
    else:
        fr_size = cpr * cluster_size
    if fr_size <= 0:
        raise ValueError("invalid file record size")
    return NtfsBoot(
        bytes_per_sector=bps,
        sectors_per_cluster=spc,
        cluster_size=cluster_size,
        mft_lcn=mft_lcn,
        file_record_size=fr_size,
    )


def _require_windows() -> None:
    if sys.platform != "win32":
        raise RuntimeError("mft_collector live mode is supported only on Windows")


class _RawVolumeReader:
    def __init__(self, drive_letter: str) -> None:
        _require_windows()
        import ctypes
        from ctypes import wintypes

        self._ctypes = ctypes
        self._wintypes = wintypes

        d = drive_letter.strip().rstrip("\\").rstrip(":").upper()
        self.drive = d
        path = rf"\\.\{d}:"

        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        FILE_SHARE_DELETE = 0x00000004
        OPEN_EXISTING = 3

        CreateFileW = ctypes.windll.kernel32.CreateFileW
        CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        CreateFileW.restype = wintypes.HANDLE

        handle = CreateFileW(
            path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            0,
            None,
        )

        INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
        if handle == 0 or handle == INVALID_HANDLE_VALUE:
            err = ctypes.windll.kernel32.GetLastError()
            raise PermissionError(f"CreateFile({path}) failed (err={err}). Run as Administrator.")

        self.handle = handle

    def close(self) -> None:
        import ctypes

        if getattr(self, "handle", None):
            ctypes.windll.kernel32.CloseHandle(self.handle)
            self.handle = None

    def read_at(self, offset: int, size: int) -> bytes:
        import ctypes
        from ctypes import wintypes

        if offset < 0:
            raise ValueError("offset must be >= 0")
        if size <= 0:
            return b""

        # Move file pointer
        SetFilePointerEx = ctypes.windll.kernel32.SetFilePointerEx
        SetFilePointerEx.argtypes = [wintypes.HANDLE, ctypes.c_longlong, ctypes.POINTER(ctypes.c_longlong), wintypes.DWORD]
        SetFilePointerEx.restype = wintypes.BOOL
        newpos = ctypes.c_longlong()
        ok = SetFilePointerEx(self.handle, ctypes.c_longlong(offset), ctypes.byref(newpos), 0)
        if not ok:
            err = ctypes.windll.kernel32.GetLastError()
            raise OSError(f"SetFilePointerEx failed (err={err})")

        buf = ctypes.create_string_buffer(size)
        read = wintypes.DWORD(0)
        ReadFile = ctypes.windll.kernel32.ReadFile
        ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
        ReadFile.restype = wintypes.BOOL
        ok = ReadFile(self.handle, buf, size, ctypes.byref(read), None)
        if not ok:
            err = ctypes.windll.kernel32.GetLastError()
            raise OSError(f"ReadFile failed (err={err})")
        return buf.raw[: int(read.value)]

    def __enter__(self) -> "_RawVolumeReader":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def _parse_runlist(runlist: bytes) -> list[tuple[int, int]]:
    """
    NTFS runlist: list of (lcn, length_in_clusters).
    """
    out: list[tuple[int, int]] = []
    i = 0
    prev_lcn = 0
    while i < len(runlist):
        hdr = runlist[i]
        i += 1
        if hdr == 0:
            break
        len_sz = hdr & 0x0F
        off_sz = (hdr >> 4) & 0x0F
        if len_sz == 0 or i + len_sz + off_sz > len(runlist):
            break
        run_len = int.from_bytes(runlist[i : i + len_sz], "little", signed=False)
        i += len_sz
        run_off = int.from_bytes(runlist[i : i + off_sz], "little", signed=True) if off_sz else 0
        i += off_sz
        lcn = prev_lcn + run_off
        prev_lcn = lcn
        out.append((lcn, run_len))
    return out


def _extract_mft_runlist_from_file_record(fr: bytes) -> tuple[int, list[tuple[int, int]]]:
    """
    Parse $MFT record 0's unnamed $DATA attribute runlist and its real size.
    Returns (real_size_bytes, runs).
    """
    if fr[:4] != b"FILE":
        raise ValueError("invalid FILE record magic for $MFT")
    first_attr_off = int.from_bytes(fr[20:22], "little", signed=False)
    off = first_attr_off
    real_size = 0
    runs: list[tuple[int, int]] = []

    while off + 16 <= len(fr):
        atype = _le_u32(fr, off)
        if atype == ATTR_TYPE_END:
            break
        alen = _le_u32(fr, off + 4)
        if alen <= 0 or off + alen > len(fr):
            break
        nonresident = fr[off + 8]
        name_len = fr[off + 9]
        # name_off = _le_u16(fr, off + 10)

        if atype == ATTR_TYPE_DATA and name_len == 0 and nonresident == 1:
            # data_run_off at +32
            data_run_off = _le_u16(fr, off + 32)
            real_size = int.from_bytes(fr[off + 48 : off + 56], "little", signed=False)
            rl = fr[off + data_run_off : off + alen]
            runs = _parse_runlist(rl)
            break
        off += alen

    if not runs or real_size <= 0:
        raise ValueError("could not locate $DATA runlist for $MFT")
    return real_size, runs


def _dump_mft_from_raw_volume(
    drive_letter: str,
    out_path: Path,
    *,
    max_bytes: int,
) -> dict[str, Any]:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with _RawVolumeReader(drive_letter) as rv:
        bs = rv.read_at(0, 512)
        boot = _parse_ntfs_bootsector(bs)

        mft0_off = boot.mft_lcn * boot.cluster_size
        fr0 = rv.read_at(mft0_off, boot.file_record_size)
        real_size, runs = _extract_mft_runlist_from_file_record(fr0)
        to_copy = min(int(real_size), int(max_bytes))

        copied = 0
        with open(out_path, "wb") as w:
            for lcn, clen in runs:
                if copied >= to_copy:
                    break
                if lcn <= 0 or clen <= 0:
                    continue
                run_bytes = clen * boot.cluster_size
                want = min(run_bytes, to_copy - copied)
                raw = rv.read_at(lcn * boot.cluster_size, want)
                w.write(raw)
                copied += len(raw)
                if len(raw) < want:
                    break

        return {
            "drive": drive_letter,
            "boot": {
                "bytes_per_sector": boot.bytes_per_sector,
                "sectors_per_cluster": boot.sectors_per_cluster,
                "cluster_size": boot.cluster_size,
                "mft_lcn": boot.mft_lcn,
                "file_record_size": boot.file_record_size,
            },
            "mft": {
                "real_size_bytes": int(real_size),
                "copied_bytes": int(copied),
                "truncated": bool(copied < real_size),
                "run_count": len(runs),
            },
            "out_path": str(out_path),
        }


def _run_parsemft(mft_path: Path, out_dir: Path, *, fmt: str, anomaly: bool, inmemory: bool) -> dict[str, Any]:
    """
    Uses parseMFT CLI (installed via pip as parseMFT).
    We call it as a module when possible.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"parseMFT.{fmt}"

    # parseMFT is historically a script `parseMFT.py` in the package.
    # Try: python -m parseMFT (some installs), else python -c import.
    flags = []
    if fmt == "csv":
        flags.append("-c")
    elif fmt == "json":
        flags.append("-j")
    elif fmt == "timeline":
        flags.append("-t")
    elif fmt == "bodyfile":
        flags.append("-b")
    else:
        flags.append("-c")
        fmt = "csv"
        out_file = out_dir / "parseMFT.csv"

    if anomaly:
        flags.append("-a")
    if inmemory:
        flags.append("-m")

    cmd = [sys.executable, "-m", "parseMFT", *flags, "-o", os.fspath(out_file), os.fspath(mft_path)]
    p = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if p.returncode != 0:
        # Fallback: try running parseMFT.py via import location if -m doesn't exist
        cmd2 = [
            sys.executable,
            "-c",
            "import runpy,sys; sys.argv=['parseMFT.py']+sys.argv[1:]; runpy.run_module('parseMFT', run_name='__main__')",
            *flags,
            "-o",
            os.fspath(out_file),
            os.fspath(mft_path),
        ]
        p2 = subprocess.run(cmd2, capture_output=True, text=True, errors="replace")
        if p2.returncode != 0:
            raise RuntimeError(f"parseMFT failed: rc={p.returncode} stderr={p.stderr[-400:]} | fallback rc={p2.returncode} stderr={p2.stderr[-400:]}")
        return {"cmd": cmd2, "returncode": p2.returncode, "stdout": p2.stdout[-2000:], "stderr": p2.stderr[-2000:], "out_file": str(out_file)}

    return {"cmd": cmd, "returncode": p.returncode, "stdout": p.stdout[-2000:], "stderr": p.stderr[-2000:], "out_file": str(out_file)}


class MftCollector(BaseCollector):
    name = "mft_collector"
    version = "0.1.0"
    description = r"Extract $MFT via raw volume access (\\.\C:) and parse via parseMFT."

    supports_live = True
    supports_path = True

    async def collect_live(self, ctx: CollectorContext) -> dict[str, Any]:
        drive = (ctx.get_param(self.name, "drive", "C") or "C").strip()
        max_bytes = ctx.get_param_int(self.name, "max_bytes", 1024 * 1024 * 1024, min_v=10 * 1024 * 1024, max_v=50 * 1024 * 1024 * 1024)
        parse_format = (ctx.get_param(self.name, "format", "csv") or "csv").strip().lower()
        anomaly = ctx.get_param_bool(self.name, "anomaly", default=True)
        inmemory = ctx.get_param_bool(self.name, "inmemory", default=False)

        mod_dir = ctx.ensure_module_dir(self.name)
        dumped = mod_dir / f"{drive.upper().rstrip(':')}_$MFT.raw"
        dump_info = await asyncio.to_thread(_dump_mft_from_raw_volume, drive, dumped, max_bytes=max_bytes)
        parse_info = await asyncio.to_thread(_run_parsemft, dumped, mod_dir, fmt=parse_format, anomaly=anomaly, inmemory=inmemory)

        return {
            "mode": "live",
            "config": {
                "drive": drive,
                "max_bytes": max_bytes,
                "format": parse_format,
                "anomaly": anomaly,
                "inmemory": inmemory,
            },
            "dump": dump_info,
            "parseMFT": parse_info,
            "artifacts": {
                "mft_dump": str(dumped),
                "parse_output": str(parse_info.get("out_file") or ""),
            },
        }

    async def collect_path(self, ctx: CollectorContext, root: Path) -> dict[str, Any]:
        parse_format = (ctx.get_param(self.name, "format", "csv") or "csv").strip().lower()
        anomaly = ctx.get_param_bool(self.name, "anomaly", default=True)
        inmemory = ctx.get_param_bool(self.name, "inmemory", default=False)

        mft = root if root.is_file() else (root / "$MFT")
        if not mft.exists():
            raise FileNotFoundError(f"$MFT not found at: {mft}")

        mod_dir = ctx.ensure_module_dir(self.name)
        parse_info = await asyncio.to_thread(_run_parsemft, mft, mod_dir, fmt=parse_format, anomaly=anomaly, inmemory=inmemory)
        return {
            "mode": "path",
            "config": {"format": parse_format, "anomaly": anomaly, "inmemory": inmemory},
            "mft_path": str(mft),
            "parseMFT": parse_info,
            "artifacts": {"parse_output": str(parse_info.get("out_file") or "")},
        }


def get_collector() -> BaseCollector:
    return MftCollector()

