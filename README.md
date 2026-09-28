# FTIT — File Type Identification Tool

Identifies a file's *real* type from its magic-number header, regardless of what its extension claims. Flags extension mismatches, disguised executables, and double-extension tricks (`invoice.pdf.exe`).

## Why

An extension is just a label — nothing stops a `.exe` from being renamed `.jpg`. FTIT reads the actual byte header (and peeks inside ZIP-based formats like `.docx`/`.apk`/`.jar`) to tell you what a file *actually* is, then scores the mismatch by risk.

## Install

No dependencies beyond the Python 3 standard library.

```bash
git clone https://github.com/raphael2517/ftito
cd ftito
python3 fileid.py --help
```

## Usage

```bash
python3 fileid.py <file_or_directory> [options]
```

| Flag | Description |
|---|---|
| `-r`, `--recursive` | Scan directories recursively |
| `-j`, `--json` | Output results as JSON |
| `-v`, `--verbose` | Show all files, including clean ones |
| `-x`, `--hex` | Show a hex dump of the file header |
| `--list` | Print all known signatures and exit |

### Examples

```bash
# Scan a directory recursively
python3 fileid.py ./downloads -r

# JSON output for scripting/CI
python3 fileid.py ./uploads -r -j > report.json

# Inspect a single suspicious file with a hex dump
python3 fileid.py suspicious.jpg -x
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | All files clean |
| `1` | One or more suspicious files found |
| `2` | Error during scan |

## What it detects

~50 file signatures across executables, archives, images, video, audio, documents, and data/cert formats — including ZIP-container refinement (`.docx`/`.xlsx`/`.pptx`/`.apk`/`.jar` vs. plain `.zip`) and RIFF sub-type detection (`WAV`/`AVI`/`WebP`).

Risk levels:
- **high** — executable disguised as another type, or a double extension (`report.pdf.exe`)
- **medium** — archive disguised as a document/image/media file
- **low** — unrecognized/obfuscated content, or a milder category mismatch
- **clean** — extension matches actual content

## License

MIT
