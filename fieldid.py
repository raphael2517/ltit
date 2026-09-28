#!/usr/bin/env python3
"""
FTIT — File Type Identification Tool Using Magic Numbers
========================================================
Reads raw file headers and identifies the true file type
regardless of the file extension.

Usage:
    python3 fileid.py <file_or_directory> [options]

Options:
    -r, --recursive     Scan directories recursively
    -j, --json          Output results as JSON
    -v, --verbose       Show all files including clean ones
    -x, --hex           Show hex dump of file header
    --list              Print all known signatures and exit

Exit codes:
    0 — all files clean
    1 — one or more suspicious files found
    2 — error during scan
"""

import os
import sys
import json
import hashlib
import argparse
import zipfile
import struct
from dataclasses import dataclass, field, asdict
from typing import Optional
from pathlib import Path


# ─────────────────────────────────────────────────────────────
# MAGIC NUMBER DATABASE
# Each entry: (offset, magic_bytes, label, extensions, category)
# category: "document" | "image" | "audio" | "video" |
#           "archive" | "executable" | "data" | "text"
# ─────────────────────────────────────────────────────────────

MAGIC_DB = [
    # ── Executables (checked first — highest risk) ──────────
    (0, b"MZ",                          "Windows PE / DOS executable",
     {".exe", ".dll", ".sys", ".scr", ".com"}, "executable"),
    (0, b"\x7fELF",                     "ELF executable (Linux/BSD)",
     {".elf", ".so", ".axf"},            "executable"),
    (0, b"\xfe\xed\xfa\xce",            "Mach-O 32-bit executable (macOS)",
     {".macho"},                          "executable"),
    (0, b"\xfe\xed\xfa\xcf",            "Mach-O 64-bit executable (macOS)",
     {".macho"},                          "executable"),
    (0, b"\xce\xfa\xed\xfe",            "Mach-O 32-bit LE executable (macOS)",
     {".macho"},                          "executable"),
    (0, b"\xcf\xfa\xed\xfe",            "Mach-O 64-bit LE executable (macOS)",
     {".macho"},                          "executable"),
    (0, b"\xca\xfe\xba\xbe",            "Java class file / Mach-O universal binary",
     {".class"},                          "executable"),
    (0, b"#!",                           "Shell script (shebang)",
     {".sh", ".bash", ".zsh", ".py", ".pl", ".rb"}, "executable"),

    # ── Archives ────────────────────────────────────────────
    (0, b"PK\x03\x04",                  "ZIP archive",
     {".zip", ".jar", ".apk", ".docx", ".xlsx",
      ".pptx", ".odt", ".ods"},          "archive"),
    (0, b"PK\x05\x06",                  "ZIP archive (empty)",
     {".zip"},                            "archive"),
    (0, b"PK\x07\x08",                  "ZIP archive (spanned)",
     {".zip"},                            "archive"),
    (0, b"\x1f\x8b",                    "gzip compressed data",
     {".gz", ".tgz"},                    "archive"),
    (0, b"BZh",                          "bzip2 compressed data",
     {".bz2"},                            "archive"),
    (0, b"\xfd7zXZ\x00",               "XZ compressed data",
     {".xz"},                             "archive"),
    (0, b"7z\xbc\xaf'\x1c",            "7-Zip archive",
     {".7z"},                             "archive"),
    (0, b"Rar!\x1a\x07\x00",           "RAR archive (v4)",
     {".rar"},                            "archive"),
    (0, b"Rar!\x1a\x07\x01\x00",       "RAR archive (v5)",
     {".rar"},                            "archive"),
    (257, b"ustar",                      "TAR archive",
     {".tar"},                            "archive"),

    # ── Images ──────────────────────────────────────────────
    (0, b"\xff\xd8\xff",                "JPEG image",
     {".jpg", ".jpeg", ".jfif"},         "image"),
    (0, b"\x89PNG\r\n\x1a\n",          "PNG image",
     {".png"},                            "image"),
    (0, b"GIF87a",                       "GIF image (87a)",
     {".gif"},                            "image"),
    (0, b"GIF89a",                       "GIF image (89a)",
     {".gif"},                            "image"),
    (0, b"BM",                           "BMP image",
     {".bmp"},                            "image"),
    (0, b"II\x2a\x00",                  "TIFF image (little-endian)",
     {".tif", ".tiff"},                  "image"),
    (0, b"MM\x00\x2a",                  "TIFF image (big-endian)",
     {".tif", ".tiff"},                  "image"),
    (0, b"RIFF",                         "RIFF container (WAV/AVI/WebP)",
     {".wav", ".avi", ".webp"},          "image"),   # refined below
    (0, b"\x00\x00\x01\x00",            "ICO image",
     {".ico"},                            "image"),
    (0, b"8BPS",                         "Adobe Photoshop document",
     {".psd"},                            "image"),

    # ── Video ───────────────────────────────────────────────
    (4, b"ftyp",                         "MP4 / MPEG-4 video",
     {".mp4", ".m4v", ".m4a", ".mov",
      ".3gp", ".3g2"},                   "video"),
    (0, b"\x1a\x45\xdf\xa3",           "Matroska / WebM video",
     {".mkv", ".webm"},                  "video"),
    (0, b"FLV\x01",                     "Flash video",
     {".flv"},                            "video"),
    (0, b"OggS",                         "Ogg container (video/audio)",
     {".ogg", ".ogv", ".oga"},           "video"),

    # ── Audio ───────────────────────────────────────────────
    (0, b"ID3",                          "MP3 audio (ID3 tag)",
     {".mp3"},                            "audio"),
    (0, b"\xff\xfb",                    "MP3 audio (frame sync)",
     {".mp3"},                            "audio"),
    (0, b"fLaC",                         "FLAC audio",
     {".flac"},                           "audio"),

    # ── Documents ───────────────────────────────────────────
    (0, b"%PDF",                         "PDF document",
     {".pdf"},                            "document"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
                                         "Microsoft OLE2 compound document "
                                         "(legacy Office / MSG)",
     {".doc", ".xls", ".ppt", ".msg",
      ".msi"},                            "document"),
    (0, b"{\x5c rtf",                   "Rich Text Format document",
     {".rtf"},                            "document"),

    # ── Data / databases ────────────────────────────────────
    (0, b"SQLite format 3\x00",         "SQLite 3 database",
     {".sqlite", ".sqlite3", ".db"},     "data"),
    (0, b"\x53\x51\x4c",               "SQLite (alt header)",
     {".sqlite"},                         "data"),
    (0, b"CAFEBABE",                     "Java / Dalvik (alt text match)",
     {".class", ".dex"},                 "data"),
    (0, b"\x64\x65\x78\x0a",           "Android DEX bytecode",
     {".dex"},                            "data"),
    (0, b"PGDMP",                        "PostgreSQL dump",
     {".dump", ".pgdump"},               "data"),

    # ── Certificates / keys ─────────────────────────────────
    (0, b"-----BEGIN",                   "PEM encoded certificate or key",
     {".pem", ".crt", ".key", ".csr"},  "data"),
    (0, b"\x30\x82",                    "DER encoded certificate",
     {".der", ".cer"},                   "data"),

    # ── Disk images ─────────────────────────────────────────
    (0, b"OggS",                         "OGG media",
     {".ogg"},                            "data"),
    (510, b"\x55\xaa",                  "MBR / disk image",
     {".img", ".iso", ".bin"},           "data"),
    (0, b"CD001",                        "ISO 9660 CD/DVD image",
     {".iso"},                            "data"),

    # ── Fonts ───────────────────────────────────────────────
    (0, b"wOFF",                         "WOFF font",
     {".woff"},                           "data"),
    (0, b"wOF2",                         "WOFF2 font",
     {".woff2"},                          "data"),
    (0, b"\x00\x01\x00\x00\x00",       "TrueType font",
     {".ttf"},                            "data"),
    (0, b"OTTO",                         "OpenType font",
     {".otf"},                            "data"),

    # ── Compiled Python ─────────────────────────────────────
    (0, b"\x55\x0d\x0d\x0a",           "Python bytecode (3.8+)",
     {".pyc"},                            "data"),
    (0, b"\x61\x0d\x0d\x0a",           "Python bytecode (3.7)",
     {".pyc"},                            "data"),
]

# ─────────────────────────────────────────────────────────────
# EXTENSION CATEGORY MAP
# Declares what each common extension *should* be.
# Used to quickly detect category mismatches.
# ─────────────────────────────────────────────────────────────

EXT_CATEGORY = {
    # images
    ".jpg": "image",  ".jpeg": "image", ".png": "image",
    ".gif": "image",  ".bmp": "image",  ".tif": "image",
    ".tiff": "image", ".webp": "image", ".ico": "image",
    ".psd": "image",  ".svg": "image",  ".heic": "image",
    # documents
    ".pdf": "document", ".doc": "document",  ".docx": "document",
    ".xls": "document", ".xlsx": "document", ".ppt": "document",
    ".pptx": "document",".odt": "document",  ".rtf": "document",
    ".txt": "text",     ".csv": "text",      ".md": "text",
    # audio
    ".mp3": "audio",  ".wav": "audio",  ".flac": "audio",
    ".aac": "audio",  ".ogg": "audio",  ".m4a": "audio",
    # video
    ".mp4": "video",  ".mkv": "video",  ".avi": "video",
    ".mov": "video",  ".flv": "video",  ".webm": "video",
    # archives
    ".zip": "archive", ".gz": "archive",  ".tar": "archive",
    ".rar": "archive", ".7z": "archive",  ".bz2": "archive",
    ".xz": "archive",  ".jar": "archive",
    # executables
    ".exe": "executable", ".dll": "executable", ".sys": "executable",
    ".sh":  "executable", ".bat": "executable", ".ps1": "executable",
    ".elf": "executable", ".so":  "executable",
}

# Extensions that are ZIP-based Office/app containers
OOXML_MARKER = {
    "word/document.xml":       "Microsoft Word OOXML document (.docx)",
    "xl/workbook.xml":         "Microsoft Excel OOXML workbook (.xlsx)",
    "ppt/presentation.xml":    "Microsoft PowerPoint OOXML presentation (.pptx)",
    "AndroidManifest.xml":     "Android APK package",
    "META-INF/MANIFEST.MF":   "Java JAR archive",
}

# ─────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────

@dataclass
class FileResult:
    path:           str
    sha256:         str
    declared_ext:   str
    real_type:      str
    real_category:  str
    declared_category: str
    mismatch:       bool
    double_ext:     bool
    risk:           str          # "clean" | "low" | "medium" | "high"
    note:           str
    header_hex:     str = ""
    size_bytes:     int = 0


# ─────────────────────────────────────────────────────────────
# CORE ENGINE
# ─────────────────────────────────────────────────────────────

READ_SIZE = 600   # bytes — enough for all offsets in the DB


def sha256_file(path: str) -> str:
    """Return the SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError:
        return "unreadable"
    return h.hexdigest()


def read_header(path: str) -> bytes:
    """Read the first READ_SIZE bytes of a file."""
    try:
        with open(path, "rb") as f:
            return f.read(READ_SIZE)
    except OSError:
        return b""


def hex_dump(data: bytes, width: int = 16) -> str:
    """Format bytes as a compact hex dump string."""
    lines = []
    for i in range(0, min(len(data), 64), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {i:04x}  {hex_part:<{width*3}}  {asc_part}")
    return "\n".join(lines)


def refine_zip(path: str) -> Optional[str]:
    """
    A ZIP match might actually be DOCX, XLSX, APK, JAR, etc.
    Peek inside the archive to find out.
    """
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = set(zf.namelist())
            for marker, label in OOXML_MARKER.items():
                if marker in names:
                    return label
    except Exception:
        pass
    return None


def match_magic(header: bytes, path: str) -> tuple[str, str]:
    """
    Compare header against MAGIC_DB.
    Returns (label, category).
    Executables are listed first in the DB so they win on ties.
    """
    for offset, magic, label, _exts, category in MAGIC_DB:
        end = offset + len(magic)
        if len(header) >= end and header[offset:end] == magic:
            # Refine RIFF container
            if magic == b"RIFF" and len(header) >= 12:
                sub = header[8:12]
                if sub == b"WAVE":
                    return "WAV audio (RIFF)", "audio"
                if sub == b"AVI ":
                    return "AVI video (RIFF)", "video"
                if sub == b"WEBP":
                    return "WebP image (RIFF)", "image"
            # Refine ZIP container
            if magic in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
                refined = refine_zip(path)
                if refined:
                    # Derive category from refined label
                    cat = "document"
                    if "APK" in refined:
                        cat = "executable"
                    elif "JAR" in refined:
                        cat = "archive"
                    return refined, cat
                return label, category
            return label, category
    return "Unknown / plaintext", "unknown"


def has_double_extension(name: str) -> bool:
    """Detect double-extension tricks like 'report.pdf.exe'."""
    parts = name.split(".")
    if len(parts) < 3:
        return False
    # Last two parts are both known or suspicious extensions
    dangerous = {
        "exe", "dll", "bat", "cmd", "ps1", "sh",
        "vbs", "js",  "jar", "scr", "com", "pif"
    }
    return parts[-1].lower() in dangerous


def compute_risk(
    real_category: str,
    declared_category: str,
    mismatch: bool,
    double_ext: bool,
    real_type: str,
) -> tuple[str, str]:
    """
    Return (risk_level, human_note).
    risk_level: "clean" | "low" | "medium" | "high"
    """
    note_parts = []
    risk = "clean"

    if double_ext:
        note_parts.append("Double extension detected")
        risk = "high"

    if mismatch:
        if real_category == "executable":
            note_parts.append(
                f"EXECUTABLE disguised as .{declared_category} "
                f"— strong malware indicator."
            )
            risk = "high"
        elif real_category == "archive" and declared_category in (
            "image", "document", "audio", "video"
        ):
            note_parts.append(
                f"Archive disguised as {declared_category} file."
            )
            risk = "medium" if risk != "high" else risk
        elif real_category == "unknown":
            note_parts.append(
                "Unrecognised format — possibly encrypted, packed, or obfuscated."
            )
            risk = "low" if risk == "clean" else risk
        else:
            note_parts.append(
                f"Extension says {declared_category} but content is {real_category}."
            )
            risk = "low" if risk == "clean" else risk

    if not note_parts:
        note_parts.append("File type matches declared extension.")

    return risk, "  ".join(note_parts)


def analyse_file(path: str, show_hex: bool = False) -> FileResult:
    """Full analysis pipeline for a single file."""
    p           = Path(path)
    declared    = p.suffix.lower()
    name        = p.name
    header      = read_header(path)
    real_type, real_cat = match_magic(header, path)
    declared_cat = EXT_CATEGORY.get(declared, "unknown")
    mismatch    = (
        real_cat != "unknown"
        and declared_cat != "unknown"
        and real_cat != declared_cat
    )
    double_ext  = has_double_extension(name)
    risk, note  = compute_risk(
        real_cat, declared_cat, mismatch, double_ext, real_type
    )
    size        = 0
    try:
        size = os.path.getsize(path)
    except OSError:
        pass

    return FileResult(
        path=str(path),
        sha256=sha256_file(path),
        declared_ext=declared,
        real_type=real_type,
        real_category=real_cat,
        declared_category=declared_cat,
        mismatch=mismatch,
        double_ext=double_ext,
        risk=risk,
        note=note,
        header_hex=hex_dump(header) if show_hex else "",
        size_bytes=size,
    )


def collect_paths(targets: list[str], recursive: bool) -> list[str]:
    """Expand file and directory arguments into a flat list of file paths."""
    paths = []
    for t in targets:
        p = Path(t)
        if p.is_file():
            paths.append(str(p))
        elif p.is_dir():
            if recursive:
                for root, _dirs, files in os.walk(p):
                    for f in files:
                        paths.append(os.path.join(root, f))
            else:
                for item in sorted(p.iterdir()):
                    if item.is_file():
                        paths.append(str(item))
        else:
            print(f"[WARN] Not found: {t}", file=sys.stderr)
    return paths


# ─────────────────────────────────────────────────────────────
# OUTPUT / FORMATTING
# ─────────────────────────────────────────────────────────────

RISK_ICON = {
    "clean":  "[ OK ]",
    "low":    "[ ~ ]",
    "medium": "[WARN]",
    "high":   "[ !! ]",
}

RISK_ORDER = {"high": 0, "medium": 1, "low": 2, "clean": 3}


def print_result(r: FileResult, verbose: bool = False) -> None:
    """Pretty-print a single FileResult to stdout."""
    if r.risk == "clean" and not verbose:
        return

    icon = RISK_ICON[r.risk]
    print(f"\n{icon} {r.path}")
    print(f"        declared : {r.declared_ext or '(none)'}")
    print(f"        real     : {r.real_type}")
    if r.mismatch or r.double_ext:
        print(f"        note     : {r.note}")
    print(f"        sha256   : {r.sha256}")
    print(f"        size     : {r.size_bytes:,} bytes")
    if r.header_hex:
        print(f"        header   :\n{r.header_hex}")


def print_summary(results: list[FileResult]) -> None:
    total    = len(results)
    high     = sum(1 for r in results if r.risk == "high")
    medium   = sum(1 for r in results if r.risk == "medium")
    low      = sum(1 for r in results if r.risk == "low")
    clean    = sum(1 for r in results if r.risk == "clean")
    print("\n" + "─" * 60)
    print(f"  Scanned : {total} file(s)")
    print(f"  [ !! ]  : {high}   high risk")
    print(f"  [WARN]  : {medium}   medium risk")
    print(f"  [ ~ ]   : {low}   low risk")
    print(f"  [ OK ]  : {clean}   clean")
    print("─" * 60)


def print_signature_list() -> None:
    """Print the built-in signature database."""
    print(f"\n{'OFFSET':<8} {'MAGIC (hex)':<30} {'CATEGORY':<12} LABEL")
    print("─" * 78)
    for offset, magic, label, _exts, category in MAGIC_DB:
        hex_magic = magic.hex()[:28]
        print(f"{offset:<8} {hex_magic:<30} {category:<12} {label}")
    print(f"\n{len(MAGIC_DB)} signatures loaded.")


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fileid",
        description=(
            "FTIT — File Type Identification Tool Using Magic Numbers\n"
            "Identifies real file types from headers, flags extension mismatches."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("paths", nargs="*", metavar="FILE_OR_DIR",
                   help="Files or directories to scan.")
    p.add_argument("-r", "--recursive", action="store_true",
                   help="Recurse into subdirectories.")
    p.add_argument("-j", "--json", action="store_true",
                   help="Output results as JSON.")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show all files, including clean ones.")
    p.add_argument("-x", "--hex", action="store_true",
                   help="Show a hex dump of the file header.")
    p.add_argument("--list", action="store_true",
                   help="Print all known signatures and exit.")
    return p


def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    if args.list:
        print_signature_list()
        return 0

    if not args.paths:
        parser.print_help()
        return 2

    file_paths = collect_paths(args.paths, args.recursive)
    if not file_paths:
        print("[ERROR] No files found.", file=sys.stderr)
        return 2

    results = [analyse_file(fp, show_hex=args.hex) for fp in file_paths]
    results.sort(key=lambda r: RISK_ORDER[r.risk])

    if args.json:
        output = []
        for r in results:
            d = asdict(r)
            if not args.hex:
                del d["header_hex"]
            output.append(d)
        print(json.dumps(output, indent=2))
        return 1 if any(r.risk in ("high", "medium") for r in results) else 0

    print("\n FTIT — File Type Identification Tool")
    print(" Using Magic Numbers | github.com/raphael2517/ftito")
    print("─" * 60)

    for r in results:
        print_result(r, verbose=args.verbose)

    print_summary(results)

    return 1 if any(r.risk in ("high", "medium") for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())