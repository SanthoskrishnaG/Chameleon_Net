"""
Pre-packaged Valid Sample File Generators for Protocol Mimicry Engine.
Provides authentic TXT, CSV, PNG, PDF, and ZIP binary samples
for instant laboratory experimentation and testing.
"""

import io
import base64
import zipfile
import hashlib
from typing import Dict, Any


def get_sample_txt() -> bytes:
    """Generate sample incident telemetry plain text."""
    content = (
        "ANTIGRAVITY SECURITY LABORATORY - TELEMETRY REPORT\n"
        "Node ID: lab-chameleon-01 (127.0.0.1)\n"
        "Classification: Controlled Traffic Analysis Experiment\n"
        "Status: Online - Socket Stream Verification Nominal\n"
        "Checksum Verification: Active SHA-256 Byte Reassembly\n"
    )
    return content.encode("utf-8")


def get_sample_csv() -> bytes:
    """Generate sample network packet metrics CSV."""
    content = (
        "seq,timestamp_sec,src_ip,dst_ip,proto,size_bytes,flags,dpi_label\n"
        "1,0.001240,127.0.0.1,127.0.0.1,TCP,512,SYN,normal\n"
        "2,0.002810,127.0.0.1,127.0.0.1,TCP,512,ACK,normal\n"
        "3,0.015240,127.0.0.1,127.0.0.1,TCP,1024,PSH,video_stream\n"
        "4,0.028910,127.0.0.1,127.0.0.1,TCP,1400,PSH,file_transfer\n"
        "5,0.042180,127.0.0.1,127.0.0.1,TCP,64,ACK,normal\n"
    )
    return content.encode("utf-8")


def get_sample_png() -> bytes:
    """Generate valid 1x1 pixel PNG binary image."""
    return (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00"
        b"\x1f\x15c4\x00\x00\x00\rIDATx\x9cc`\x00\x00\x00\x02\x00\x01H\xaf\xa4q\x00\x00\x00\x00IEND\xaeB`\x82"
    )


def get_sample_pdf() -> bytes:
    """Generate valid minimal 1-page PDF document."""
    pdf_text = (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj\n"
        b"xref\n"
        b"0 4\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000052 00000 n \n"
        b"0000000101 00000 n \n"
        b"trailer<</Size 4/Root 1 0 R>>\n"
        b"startxref\n"
        b"178\n"
        b"%%EOF"
    )
    return pdf_text


def get_sample_zip() -> bytes:
    """Generate valid ZIP archive containing an experiment description."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("experiment_manifest.txt", "ChameleonNet Lab: Real File Transmission Archive Test\n")
    return buf.getvalue()


def get_sample_bin() -> bytes:
    """Generate sample structured binary firmware/telemetry block."""
    return bytes([(i * 17 + 42) % 256 for i in range(512)])


SAMPLE_GENERATORS = {
    "txt": ("sample_telemetry.txt", "text/plain", get_sample_txt),
    "csv": ("sample_network_trace.csv", "text/csv", get_sample_csv),
    "png": ("sample_topology.png", "image/png", get_sample_png),
    "pdf": ("sample_specification.pdf", "application/pdf", get_sample_pdf),
    "zip": ("sample_archive.zip", "application/zip", get_sample_zip),
    "other": ("sample_datagram.bin", "application/octet-stream", get_sample_bin),
}


def get_all_samples_metadata() -> Dict[str, Any]:
    """Retrieve all sample file descriptors with base64 payloads."""
    results = {}
    for key, (fname, mime, gen_func) in SAMPLE_GENERATORS.items():
        raw_bytes = gen_func()
        results[key] = {
            "category": key,
            "filename": fname,
            "mime_type": mime,
            "size_bytes": len(raw_bytes),
            "sha256": hashlib.sha256(raw_bytes).hexdigest(),
            "content_base64": base64.b64encode(raw_bytes).decode("ascii")
        }
    return results
