"""
File Validator and Content Inspector for Protocol Mimicry Engine.
Validates binary file content, detects MIME types and format categories,
verifies magic headers, and strictly forbids unsafe executable payloads.
"""

import os
import re
import io
import zipfile
from typing import Dict, Any, Tuple

# Magic Byte Signatures
MAGIC_PNG = b"\x89PNG\r\n\x1a\n"
MAGIC_JPEG = b"\xff\xd8\xff"
MAGIC_PDF = b"%PDF-"
MAGIC_ZIP_PK = b"PK\x03\x04"
MAGIC_ZIP_EMPTY = b"PK\x05\x06"
MAGIC_ZIP_SPANNED = b"PK\x07\x08"

# Disallowed Executable Signatures (Defense in Depth)
MAGIC_EXE_MZ = b"MZ"
MAGIC_ELF = b"\x7fELF"


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal or special character exploits."""
    if not filename:
        return "unnamed_transfer.bin"
    base = os.path.basename(filename.replace("\\", "/"))
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]", "_", base)
    if not cleaned or cleaned.startswith("."):
        cleaned = f"file_{cleaned}"
    return cleaned[:120]


def is_plain_text(data: bytes) -> bool:
    """Check if byte sequence is valid UTF-8/ASCII printable text."""
    if not data:
        return True
    try:
        decoded = data.decode("utf-8")
        # Ensure it doesn't contain non-printable control characters other than \t, \n, \r
        for ch in decoded[:4096]:
            cp = ord(ch)
            if cp < 32 and cp not in (9, 10, 13):
                return False
        return True
    except UnicodeDecodeError:
        return False


def is_csv(data: bytes) -> bool:
    """Check if text byte sequence resembles structured CSV/TSV."""
    if not is_plain_text(data):
        return False
    text = data.decode("utf-8", errors="ignore")
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if not lines:
        return False
    first = lines[0]
    return ("," in first or ";" in first or "\t" in first)


def validate_file_content(filename: str, data: bytes, max_bytes: int = 10 * 1024 * 1024) -> Dict[str, Any]:
    """
    Inspect raw binary bytes and validate content against format standards.
    Returns metadata dict: category, mime_type, size, is_valid.
    Raises ValueError on disallowed formats or corrupt structures.
    """
    if data is None or len(data) == 0:
        raise ValueError("File content is empty (0 bytes).")

    if len(data) > max_bytes:
        raise ValueError(f"File size ({len(data)} bytes) exceeds permitted maximum ({max_bytes} bytes).")

    # Security check: Forbid executable binaries
    if data.startswith(MAGIC_EXE_MZ):
        raise ValueError("Security violation: Windows PE/MZ executables (.exe, .dll) are forbidden.")
    if data.startswith(MAGIC_ELF):
        raise ValueError("Security violation: Linux ELF executables are forbidden.")

    ext = os.path.splitext(filename)[1].lower().lstrip(".")

    category = "other"
    detected_mime = "application/octet-stream"

    if data.startswith(MAGIC_PNG):
        category = "png"
        detected_mime = "image/png"
        if len(data) < 24:
            raise ValueError("Corrupt PNG file: File header truncated.")
    elif data.startswith(MAGIC_JPEG):
        category = "jpeg"
        detected_mime = "image/jpeg"
    elif data.startswith(MAGIC_PDF):
        category = "pdf"
        detected_mime = "application/pdf"
        if b"%%EOF" not in data[-1024:]:
            # Some PDFs may have whitespace or extra bytes after %%EOF
            if b"%%EOF" not in data:
                raise ValueError("Corrupt PDF file: Missing %%EOF trailer marker.")
    elif data.startswith(MAGIC_ZIP_PK) or data.startswith(MAGIC_ZIP_EMPTY) or data.startswith(MAGIC_ZIP_SPANNED):
        category = "zip"
        detected_mime = "application/zip"
        try:
            with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
                # Test archive integrity
                bad_file = zf.testzip()
                if bad_file:
                    raise ValueError(f"Corrupt ZIP archive: CRC mismatch in member {bad_file}.")
        except zipfile.BadZipFile as e:
            raise ValueError(f"Invalid or corrupted ZIP archive: {e}")
    elif ext in ("csv", "tsv") or is_csv(data):
        category = "csv"
        detected_mime = "text/csv"
    elif ext in ("txt", "log", "json", "md") or is_plain_text(data):
        category = "txt"
        detected_mime = "text/plain"
    else:
        # Permitted arbitrary binary file (e.g. .bin, .dat)
        category = "other"
        detected_mime = "application/octet-stream"

    return {
        "valid": True,
        "category": category,
        "mime_type": detected_mime,
        "size_bytes": len(data),
        "sanitized_filename": sanitize_filename(filename)
    }
