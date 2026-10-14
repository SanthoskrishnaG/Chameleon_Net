"""
Custom Text Payload Handler.
Provides text validation, UTF-8 chunking with binary framing headers,
padding markers, and ordered byte-level reassembly with UDP integrity reporting.
"""

import os
import struct
from typing import Dict, Any, List, Tuple, Optional

HEADER_MAGIC = b"MIMC"
HEADER_FORMAT = "!4sIIHH"  # MAGIC (4B), seq (4B), total_chunks (4B), data_len (2B), flags (2B)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 16 bytes

FLAG_PADDED = 0x0001
FLAG_LAST = 0x0002
FLAG_REPEAT = 0x0004


def validate_text(text: str) -> str:
    """
    Validate input text according to safety constraints:
    - Non-empty
    - <= 5000 characters
    - No disallowed control characters
    """
    if not isinstance(text, str):
        raise ValueError("Input must be a text string.")
    
    text_clean = text.strip()
    if len(text_clean) == 0:
        raise ValueError("Payload text cannot be empty.")
    
    if len(text) > 5000:
        raise ValueError(f"Payload text length ({len(text)}) exceeds maximum allowed (5000 characters).")
    
    # Check for disallowed ASCII control characters (allow \n, \r, \t)
    for char in text:
        cp = ord(char)
        if (cp < 32 and cp not in (9, 10, 13)) or cp == 127:
            raise ValueError(f"Payload contains disallowed control character (ASCII {cp}).")
            
    return text


def chunk_text(
    text: str,
    packet_size: int,
    repeat_to_count: int = 0,
    pad_last: bool = True
) -> List[bytes]:
    """
    Encode text to UTF-8 bytes and split into framed packet chunks.
    Ensures every packet has length == packet_size (or natural chunk size)
    with a structured header carrying the exact payload byte length.
    """
    validated = validate_text(text)
    raw_bytes = validated.encode("utf-8")
    
    chunk_capacity = max(8, packet_size - HEADER_SIZE)
    
    if repeat_to_count > 0:
        needed_bytes = chunk_capacity * repeat_to_count
        if len(raw_bytes) < needed_bytes:
            repetitions = (needed_bytes // len(raw_bytes)) + 2
            repeated_bytes = (raw_bytes + b" ") * repetitions
            raw_bytes = repeated_bytes[:needed_bytes]
            
    chunks_data = [
        raw_bytes[i:i + chunk_capacity]
        for i in range(0, len(raw_bytes), chunk_capacity)
    ]
    
    if not chunks_data:
        chunks_data = [b""]

    total_chunks = len(chunks_data)
    packet_list: List[bytes] = []

    for seq, chunk in enumerate(chunks_data):
        data_len = len(chunk)
        flags = 0
        if seq == total_chunks - 1:
            flags |= FLAG_LAST
        if repeat_to_count > 0:
            flags |= FLAG_REPEAT

        # Pad chunk if requested or to meet fixed packet_size
        padding_needed = chunk_capacity - data_len
        padding = b""
        if (pad_last or seq < total_chunks - 1) and padding_needed > 0:
            # Deterministic pseudo-random padding
            flags |= FLAG_PADDED
            padding = bytes([(i * 37 + seq * 13) % 256 for i in range(padding_needed)])

        header = struct.pack(
            HEADER_FORMAT,
            HEADER_MAGIC,
            seq,
            total_chunks,
            data_len,
            flags
        )
        packet_list.append(header + chunk + padding)

    return packet_list


def preview_chunks(
    text: str,
    packet_size: int,
    repeat_to_count: int = 0,
    pad_last: bool = True
) -> Dict[str, Any]:
    """
    Generate live preview metadata of how text will be fragmented into packets.
    """
    validated = validate_text(text)
    packets = chunk_text(validated, packet_size, repeat_to_count, pad_last)
    total_bytes = len(validated.encode("utf-8"))
    
    chunk_capacity = max(8, packet_size - HEADER_SIZE)
    chunks_meta = []
    
    for seq, pkt in enumerate(packets):
        header = pkt[:HEADER_SIZE]
        magic, s, total, dlen, flags = struct.unpack(HEADER_FORMAT, header)
        payload_bytes = pkt[HEADER_SIZE:HEADER_SIZE + dlen]
        preview_str = payload_bytes.decode("utf-8", errors="replace")[:30]
        
        chunks_meta.append({
            "seq": seq + 1,
            "data_len": dlen,
            "packet_size": len(pkt),
            "padding_len": len(pkt) - HEADER_SIZE - dlen,
            "is_padded": bool(flags & FLAG_PADDED),
            "preview": preview_str,
            "hue": (seq * 47) % 360
        })

    return {
        "text_length": len(validated),
        "total_utf8_bytes": total_bytes,
        "packet_size": packet_size,
        "chunk_capacity": chunk_capacity,
        "total_packets": len(packets),
        "chunks": chunks_meta
    }


def reassemble_packets(
    packets: List[bytes],
    expected_sent_text: Optional[str] = None
) -> Dict[str, Any]:
    """
    Reassemble received packet byte array:
    - Extracts headers and strips padding
    - Assembles bytes in order before decoding UTF-8
    - Accurately tracks UDP anomalies (loss, duplication, out-of-order)
    """
    parsed_chunks: Dict[int, bytes] = {}
    total_expected = 0
    duplicate_count = 0
    out_of_order_count = 0
    last_seq_seen = -1
    malformed_count = 0

    for pkt in packets:
        if len(pkt) < HEADER_SIZE:
            malformed_count += 1
            continue
            
        header = pkt[:HEADER_SIZE]
        try:
            magic, seq, total_chunks, data_len, flags = struct.unpack(HEADER_FORMAT, header)
        except Exception:
            malformed_count += 1
            continue

        if magic != HEADER_MAGIC:
            malformed_count += 1
            continue

        if total_chunks > total_expected:
            total_expected = total_chunks

        if seq in parsed_chunks:
            duplicate_count += 1
        else:
            if last_seq_seen != -1 and seq < last_seq_seen:
                out_of_order_count += 1
            last_seq_seen = seq
            payload_data = pkt[HEADER_SIZE:HEADER_SIZE + data_len]
            parsed_chunks[seq] = payload_data

    # Reassemble bytes strictly in sequence order
    ordered_bytes = bytearray()
    missing_seqs = []
    max_seq = total_expected if total_expected > 0 else (max(parsed_chunks.keys()) + 1 if parsed_chunks else 0)

    for s in range(max_seq):
        if s in parsed_chunks:
            ordered_bytes.extend(parsed_chunks[s])
        else:
            missing_seqs.append(s)

    # Decode bytes as UTF-8 strictly or with replacement for lost gaps
    reassembled_text = ordered_bytes.decode("utf-8", errors="replace")

    integrity_match = False
    if expected_sent_text is not None:
        integrity_match = (reassembled_text == expected_sent_text)
    elif len(missing_seqs) == 0 and malformed_count == 0:
        integrity_match = True

    return {
        "received_text": reassembled_text,
        "total_expected": max_seq,
        "received_unique_packets": len(parsed_chunks),
        "total_packets_processed": len(packets),
        "lost_packets": len(missing_seqs),
        "missing_sequences": missing_seqs,
        "duplicate_packets": duplicate_count,
        "out_of_order_packets": out_of_order_count,
        "malformed_packets": malformed_count,
        "match": integrity_match
    }
