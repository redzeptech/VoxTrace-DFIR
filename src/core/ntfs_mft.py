from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


FILE_RECORD_MAGIC = b"FILE"
MFT_RECORD_SIZE = 1024

FILE_RECORD_IN_USE = 0x0001
FILE_RECORD_IS_DIRECTORY = 0x0002

ATTR_TYPE_STANDARD_INFORMATION = 0x10
ATTR_TYPE_FILE_NAME = 0x30
ATTR_TYPE_END = 0xFFFFFFFF


def _u16(b: bytes, off: int) -> int:
    return int.from_bytes(b[off : off + 2], "little", signed=False)


def _u32(b: bytes, off: int) -> int:
    return int.from_bytes(b[off : off + 4], "little", signed=False)


def _u64(b: bytes, off: int) -> int:
    return int.from_bytes(b[off : off + 8], "little", signed=False)


def filetime_to_dt_utc(filetime: int) -> datetime | None:
    # FILETIME: 100-ns intervals since 1601-01-01
    if not filetime:
        return None
    try:
        us = filetime / 10
        epoch_us = 11644473600000000  # 1601->1970 delta in microseconds
        unix_us = us - epoch_us
        if unix_us <= 0:
            return None
        return datetime.fromtimestamp(unix_us / 1_000_000, tz=timezone.utc)
    except Exception:
        return None


def dt_to_iso(dt: datetime | None) -> str | None:
    if not dt:
        return None
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()


@dataclass(frozen=True)
class MftEntry:
    recordnum: int
    flags: int
    in_use: bool
    is_directory: bool
    filename: str | None
    parent_ref: int | None
    si_times: dict[str, str | None]
    fn_times: dict[str, str | None]

    def to_dict(self) -> dict[str, Any]:
        return {
            "recordnum": self.recordnum,
            "flags": self.flags,
            "in_use": self.in_use,
            "is_directory": self.is_directory,
            "filename": self.filename,
            "parent_ref": self.parent_ref,
            "si_times": self.si_times,
            "fn_times": self.fn_times,
        }


def _parse_resident_attr_value(record: bytes, attr_off: int, attr_len: int) -> bytes | None:
    # Attribute header (common 16 bytes), resident header starts at +16
    # +16: value_len (4), +20: value_off (2)
    if attr_off + 24 > len(record):
        return None
    value_len = _u32(record, attr_off + 16)
    value_off = _u16(record, attr_off + 20)
    start = attr_off + value_off
    end = start + value_len
    if value_len <= 0 or start < 0 or end > (attr_off + attr_len) or end > len(record):
        return None
    return record[start:end]


def _parse_standard_information(value: bytes) -> dict[str, str | None]:
    if len(value) < 32:
        return {}
    cr = filetime_to_dt_utc(_u64(value, 0))
    mt = filetime_to_dt_utc(_u64(value, 8))
    ct = filetime_to_dt_utc(_u64(value, 16))
    at = filetime_to_dt_utc(_u64(value, 24))
    return {"crtime": dt_to_iso(cr), "mtime": dt_to_iso(mt), "ctime": dt_to_iso(ct), "atime": dt_to_iso(at)}


def _parse_file_name(value: bytes) -> tuple[str | None, int | None, dict[str, str | None], int | None]:
    # FILE_NAME attribute structure (resident):
    # 0x00 parent ref (8)
    # 0x08 crtime (8)
    # 0x10 mtime (8)
    # 0x18 ctime (8)
    # 0x20 atime (8)
    # 0x40 filename_len (1)
    # 0x41 namespace (1)
    # 0x42 filename (utf16le)
    if len(value) < 0x42:
        return None, None, {}, None
    parent_ref = _u64(value, 0) & 0xFFFFFFFFFFFF  # lower 6 bytes are MFT ref
    cr = filetime_to_dt_utc(_u64(value, 8))
    mt = filetime_to_dt_utc(_u64(value, 16))
    ct = filetime_to_dt_utc(_u64(value, 24))
    at = filetime_to_dt_utc(_u64(value, 32))
    name_len = value[0x40]
    namespace = value[0x41]
    name_bytes = value[0x42 : 0x42 + (name_len * 2)]
    try:
        name = name_bytes.decode("utf-16le", errors="replace")
    except Exception:
        name = None
    times = {"crtime": dt_to_iso(cr), "mtime": dt_to_iso(mt), "ctime": dt_to_iso(ct), "atime": dt_to_iso(at)}
    return name, parent_ref, times, int(namespace)


def parse_mft_record(record: bytes) -> MftEntry | None:
    if len(record) != MFT_RECORD_SIZE:
        return None
    if record[:4] != FILE_RECORD_MAGIC:
        return None
    recordnum = _u32(record, 44)
    flags = _u16(record, 22)
    in_use = bool(flags & FILE_RECORD_IN_USE)
    is_dir = bool(flags & FILE_RECORD_IS_DIRECTORY)
    first_attr_off = _u16(record, 20)
    if first_attr_off <= 0 or first_attr_off >= MFT_RECORD_SIZE:
        return None

    si_times: dict[str, str | None] = {}
    fn_times: dict[str, str | None] = {}
    filename: str | None = None
    parent_ref: int | None = None
    best_ns: int | None = None

    off = first_attr_off
    while off + 16 <= MFT_RECORD_SIZE:
        atype = _u32(record, off)
        if atype == ATTR_TYPE_END:
            break
        alen = _u32(record, off + 4)
        if alen <= 0 or off + alen > MFT_RECORD_SIZE:
            break
        nonresident = record[off + 8]
        if nonresident == 0:
            value = _parse_resident_attr_value(record, off, alen)
            if value is not None:
                if atype == ATTR_TYPE_STANDARD_INFORMATION and not si_times:
                    si_times = _parse_standard_information(value)
                elif atype == ATTR_TYPE_FILE_NAME:
                    name, pref, times, ns = _parse_file_name(value)
                    # Prefer Win32 namespace (1) when possible, else first non-empty.
                    if name:
                        if filename is None or (ns is not None and ns == 1 and best_ns != 1):
                            filename = name
                            parent_ref = pref
                            fn_times = times
                            best_ns = ns
        off += alen

    return MftEntry(
        recordnum=recordnum,
        flags=flags,
        in_use=in_use,
        is_directory=is_dir,
        filename=filename,
        parent_ref=parent_ref,
        si_times=si_times,
        fn_times=fn_times,
    )


def iter_mft_entries(mft_path: Path, *, max_records: int | None = None) -> Iterator[MftEntry]:
    with open(mft_path, "rb") as f:
        i = 0
        while True:
            if max_records is not None and i >= max_records:
                break
            chunk = f.read(MFT_RECORD_SIZE)
            if not chunk or len(chunk) < MFT_RECORD_SIZE:
                break
            ent = parse_mft_record(chunk)
            if ent is not None:
                yield ent
            i += 1

