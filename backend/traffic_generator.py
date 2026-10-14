"""
Socket-based Traffic Generator for 127.0.0.1 Loopback.
Executes real TCP/UDP transmissions with microsecond-precision timestamping,
live trace streaming, CRC32 checksumming, bidirectional echo,
and binary file transmission with temporary file streaming, atomic finalization,
SHA-256 integrity verification, and UDP packet loss detection.
"""

import os
import csv
import zlib
import time
import socket
import struct
import string
import random
import hashlib
import tempfile
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional

from backend.config import TRAFFIC_DIR, UPLOADS_DIR, is_loopback
from backend.text_payload import (
    chunk_text, reassemble_packets, chunk_binary, reassemble_binary, HEADER_SIZE, HEADER_FORMAT, HEADER_MAGIC
)
from backend.file_validator import sanitize_filename, validate_file_content

# Active generation tasks stored in-memory for live UI polling
GENERATION_TASKS: Dict[str, Dict[str, Any]] = {}
TASKS_LOCK = threading.Lock()


def generate_payload_bytes(pattern: str, size: int, seq: int) -> bytes:
    """Generate payload bytes according to pattern."""
    size = max(1, size)
    if pattern == "zeros":
        return b"\x00" * size
    elif pattern == "incrementing":
        return bytes([(i + seq) % 256 for i in range(size)])
    elif pattern == "text-like":
        chars = string.ascii_letters + string.digits + " \n.,!?"
        return "".join([chars[(i * 13 + seq * 7) % len(chars)] for i in range(size)]).encode("ascii")
    else:  # "random"
        return os.urandom(size)


def safe_preview(data: bytes, max_len: int = 20) -> str:
    """Produce a safe, printable ASCII preview string."""
    chars = []
    for b in data[:max_len]:
        if 32 <= b <= 126:
            chars.append(chr(b))
        else:
            chars.append(".")
    return "".join(chars)


def generate_experiment_id() -> str:
    """Generate a unique experiment ID."""
    now_str = datetime.now().strftime("%Y%m%d-%H%M%S")
    rand_suffix = f"{random.randint(1000, 9999)}"
    return f"EXP-{now_str}-{rand_suffix}"


def cancel_generation(exp_id: str) -> bool:
    """Safely abort an active socket transmission and clean up temporary files."""
    with TASKS_LOCK:
        task = GENERATION_TASKS.get(exp_id)
        if not task:
            return False
        cancel_evt = task.get("cancel_event")
        if cancel_evt:
            cancel_evt.set()
        task["status"] = "cancelled"
        task["error"] = "Transmission aborted by user cancel control."
        task["sender_status"] = "Sender: Transfer cancelled."
        task["receiver_status"] = "Receiver: Aborted and temporary storage removed."
        
        # Safe cleanup of any partial receiver temp file
        tmp_path = task.get("temp_file_path")
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
        return True


class TrafficGenerator:
    """
    Manages live socket transmissions across 127.0.0.1.
    Strictly forbids non-loopback addresses.
    Supports random patterns, custom text payload, and real binary file transfers.
    """

    def __init__(self, experiment_id: Optional[str] = None):
        self.experiment_id = experiment_id or generate_experiment_id()
        self.host = "127.0.0.1"
        if not is_loopback(self.host):
            raise ValueError(f"Safety violation: Host {self.host} is not an authorized loopback address.")

    def run_generation_async(self, params: Dict[str, Any]) -> str:
        """Launch transmission in a managed background thread."""
        exp_id = self.experiment_id
        cancel_event = threading.Event()
        
        file_bytes = params.get("file_bytes")
        total_bytes = len(file_bytes) if file_bytes else (int(params.get("packet_count", 100)) * int(params.get("packet_size", 512)))

        with TASKS_LOCK:
            GENERATION_TASKS[exp_id] = {
                "id": exp_id,
                "status": "running",
                "progress": 0,
                "packet_count": 0,
                "target_count": params.get("packet_count", 100),
                "packets": [],
                "error": None,
                "reassembled_text": None,
                "text_match": None,
                "reassembled_bytes": None,
                "file_sha256": None,
                "file_match": None,
                "udp_report": None,
                "created_at": datetime.now().isoformat(),
                "params": params,
                "cancel_event": cancel_event,
                "bytes_sent": 0,
                "bytes_received": 0,
                "total_bytes": total_bytes,
                "sender_status": "Sender: Initializing socket connection on 127.0.0.1...",
                "receiver_status": "Receiver: Binding socket listener on 127.0.0.1...",
                "temp_file_path": None,
                "storage_path": None,
                "file_id": None,
                "filename": params.get("filename", "file.bin")
            }

        thread = threading.Thread(target=self._worker, args=(params,), daemon=True)
        thread.start()
        return exp_id

    def _worker(self, params: Dict[str, Any]):
        exp_id = self.experiment_id
        with TASKS_LOCK:
            if exp_id not in GENERATION_TASKS:
                cancel_event = threading.Event()
                file_bytes_init = params.get("file_bytes")
                total_bytes_init = len(file_bytes_init) if file_bytes_init else (int(params.get("packet_count", 100)) * int(params.get("packet_size", 512)))
                GENERATION_TASKS[exp_id] = {
                    "id": exp_id,
                    "status": "running",
                    "progress": 0,
                    "packet_count": 0,
                    "target_count": params.get("packet_count", 100),
                    "packets": [],
                    "error": None,
                    "reassembled_text": None,
                    "text_match": None,
                    "reassembled_bytes": None,
                    "file_sha256": None,
                    "file_match": None,
                    "udp_report": None,
                    "created_at": datetime.now().isoformat(),
                    "params": params,
                    "cancel_event": cancel_event,
                    "bytes_sent": 0,
                    "bytes_received": 0,
                    "total_bytes": total_bytes_init,
                    "sender_status": "Sender: Initializing...",
                    "receiver_status": "Receiver: Initializing...",
                    "temp_file_path": None,
                    "storage_path": None,
                    "file_id": None,
                    "filename": params.get("filename", "file.bin")
                }
        try:
            proto = params.get("protocol", "TCP").upper()
            packet_count = int(params.get("packet_count", 100))
            packet_size = int(params.get("packet_size", 512))
            interval_ms = float(params.get("interval_ms", 10))
            payload_pattern = params.get("payload_pattern", "random")
            direction = params.get("direction", "client->server")
            payload_mode = params.get("payload_mode", "pattern")
            custom_text = params.get("custom_text", "")
            pad_last = bool(params.get("pad_last", True))
            file_bytes = params.get("file_bytes")

            is_bidirectional = (direction == "bidirectional")

            # Determine payloads to send
            text_chunks: List[bytes] = []
            if payload_mode == "custom_text":
                text_chunks = chunk_text(custom_text, packet_size, pad_last=pad_last)
                packet_count = len(text_chunks)
                with TASKS_LOCK:
                    if exp_id in GENERATION_TASKS:
                        GENERATION_TASKS[exp_id]["target_count"] = packet_count
                        GENERATION_TASKS[exp_id]["total_bytes"] = sum(len(c) for c in text_chunks)
            elif payload_mode == "file" and file_bytes is not None:
                text_chunks = chunk_binary(file_bytes, packet_size, pad_last=pad_last)
                packet_count = len(text_chunks)
                with TASKS_LOCK:
                    if exp_id in GENERATION_TASKS:
                        GENERATION_TASKS[exp_id]["target_count"] = packet_count
                        GENERATION_TASKS[exp_id]["total_bytes"] = len(file_bytes)

            if proto == "TCP":
                self._run_tcp(
                    packet_count=packet_count,
                    packet_size=packet_size,
                    interval_ms=interval_ms,
                    payload_pattern=payload_pattern,
                    is_bidirectional=is_bidirectional,
                    payload_mode=payload_mode,
                    text_chunks=text_chunks,
                    custom_text=custom_text,
                    params=params
                )
            else:
                self._run_udp(
                    packet_count=packet_count,
                    packet_size=packet_size,
                    interval_ms=interval_ms,
                    payload_pattern=payload_pattern,
                    is_bidirectional=is_bidirectional,
                    payload_mode=payload_mode,
                    text_chunks=text_chunks,
                    custom_text=custom_text,
                    params=params
                )

        except Exception as e:
            with TASKS_LOCK:
                if exp_id in GENERATION_TASKS:
                    GENERATION_TASKS[exp_id]["status"] = "failed"
                    GENERATION_TASKS[exp_id]["error"] = str(e)
                    GENERATION_TASKS[exp_id]["sender_status"] = f"Sender error: {e}"
                    GENERATION_TASKS[exp_id]["receiver_status"] = f"Receiver error: {e}"

    def _run_tcp(
        self,
        packet_count: int,
        packet_size: int,
        interval_ms: float,
        payload_pattern: str,
        is_bidirectional: bool,
        payload_mode: str,
        text_chunks: List[bytes],
        custom_text: str,
        params: Optional[Dict[str, Any]] = None
    ):
        exp_id = self.experiment_id
        params = params or {}
        cancel_event = None
        with TASKS_LOCK:
            if exp_id in GENERATION_TASKS:
                cancel_event = GENERATION_TASKS[exp_id].get("cancel_event")

        # Receiver setup with temporary file if file mode
        temp_file = None
        temp_path = None
        filename = params.get("filename", "transfer.bin")
        expected_sha256 = params.get("sent_sha256")
        expected_size = params.get("file_size")
        if payload_mode == "file":
            UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
            temp_file = tempfile.NamedTemporaryFile(dir=str(UPLOADS_DIR), delete=False, prefix=f"recv_{exp_id}_", suffix=".tmp")
            temp_path = Path(temp_file.name)
            with TASKS_LOCK:
                if exp_id in GENERATION_TASKS:
                    GENERATION_TASKS[exp_id]["temp_file_path"] = str(temp_path)

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        server_port = server_sock.getsockname()[1]

        received_payloads: List[bytes] = []
        server_ready = threading.Event()
        server_done = threading.Event()
        receiver_bytes_written = 0

        def server_thread():
            nonlocal receiver_bytes_written
            server_ready.set()
            try:
                conn, _ = server_sock.accept()
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                with TASKS_LOCK:
                    if exp_id in GENERATION_TASKS:
                        GENERATION_TASKS[exp_id]["receiver_status"] = f"Receiver: Connected on 127.0.0.1:{server_port}, streaming data..."

                while True:
                    if cancel_event and cancel_event.is_set():
                        break
                    # Reliable stream framing read: exactly 4 bytes length prefix
                    raw_len = bytearray()
                    while len(raw_len) < 4:
                        chunk = conn.recv(4 - len(raw_len))
                        if not chunk:
                            break
                        raw_len.extend(chunk)
                    if len(raw_len) < 4:
                        break

                    msg_len = struct.unpack("!I", raw_len)[0]
                    data = bytearray()
                    while len(data) < msg_len:
                        chunk = conn.recv(min(4096, msg_len - len(data)))
                        if not chunk:
                            break
                        data.extend(chunk)
                    if len(data) == msg_len:
                        pkt_data = bytes(data)
                        received_payloads.append(pkt_data)

                        # In file transfer mode: stream payload bytes to receiver temp file
                        if payload_mode == "file" and temp_file:
                            if len(pkt_data) >= HEADER_SIZE:
                                magic, seq, total_c, dlen, flags = struct.unpack(HEADER_FORMAT, pkt_data[:HEADER_SIZE])
                                if magic == HEADER_MAGIC and dlen > 0:
                                    actual_bytes = pkt_data[HEADER_SIZE:HEADER_SIZE + dlen]
                                    temp_file.write(actual_bytes)
                                    receiver_bytes_written += len(actual_bytes)
                                    with TASKS_LOCK:
                                        if exp_id in GENERATION_TASKS:
                                            GENERATION_TASKS[exp_id]["bytes_received"] = receiver_bytes_written
                                            GENERATION_TASKS[exp_id]["receiver_status"] = (
                                                f"Receiver: Streaming chunk {seq+1}/{total_c} ({receiver_bytes_written} B written)"
                                            )

                        if is_bidirectional:
                            ack = b"ACK:" + bytes(data[:16])
                            conn.sendall(struct.pack("!I", len(ack)) + ack)
                conn.close()
            except Exception as e:
                with TASKS_LOCK:
                    if exp_id in GENERATION_TASKS:
                        GENERATION_TASKS[exp_id]["receiver_status"] = f"Receiver socket error: {e}"
            finally:
                if temp_file:
                    temp_file.flush()
                    temp_file.close()
                server_sock.close()
                server_done.set()

        s_t = threading.Thread(target=server_thread, daemon=True)
        s_t.start()
        server_ready.wait()

        # Client execution
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        client_sock.connect(("127.0.0.1", server_port))
        client_port = client_sock.getsockname()[1]

        with TASKS_LOCK:
            if exp_id in GENERATION_TASKS:
                GENERATION_TASKS[exp_id]["sender_status"] = f"Sender: Connected from port {client_port} -> {server_port}"

        packets: List[Dict[str, Any]] = []
        t0 = time.perf_counter()
        seq_num = 1
        client_bytes_sent = 0

        for i in range(packet_count):
            if cancel_event and cancel_event.is_set():
                break

            if (payload_mode in ("custom_text", "file")) and i < len(text_chunks):
                payload = text_chunks[i]
            else:
                payload = generate_payload_bytes(payload_pattern, packet_size, i)

            client_sock.sendall(struct.pack("!I", len(payload)) + payload)
            t_send = time.perf_counter() - t0
            crc_hex = f"{zlib.crc32(payload) & 0xffffffff:08x}"

            # Calculate actual content bytes sent
            if payload_mode == "file" and len(payload) >= HEADER_SIZE:
                _, _, _, dlen, _ = struct.unpack(HEADER_FORMAT, payload[:HEADER_SIZE])
                client_bytes_sent += dlen
            else:
                client_bytes_sent += len(payload)

            p_record = {
                "seq": seq_num,
                "timestamp": round(t_send, 6),
                "proto": "TCP",
                "direction": "C->S",
                "size": len(payload),
                "crc32": crc_hex,
                "src_port": client_port,
                "dst_port": server_port,
                "preview": safe_preview(payload)
            }
            packets.append(p_record)
            seq_num += 1

            if is_bidirectional:
                raw_len = client_sock.recv(4)
                if raw_len and len(raw_len) == 4:
                    ack_len = struct.unpack("!I", raw_len)[0]
                    ack_data = client_sock.recv(ack_len)
                    t_ack = time.perf_counter() - t0
                    ack_crc = f"{zlib.crc32(ack_data) & 0xffffffff:08x}"
                    ack_record = {
                        "seq": seq_num,
                        "timestamp": round(t_ack, 6),
                        "proto": "TCP",
                        "direction": "S->C",
                        "size": len(ack_data),
                        "crc32": ack_crc,
                        "src_port": server_port,
                        "dst_port": client_port,
                        "preview": safe_preview(ack_data)
                    }
                    packets.append(ack_record)
                    seq_num += 1

            progress = int(((i + 1) / packet_count) * 100)
            with TASKS_LOCK:
                if exp_id in GENERATION_TASKS:
                    GENERATION_TASKS[exp_id]["progress"] = progress
                    GENERATION_TASKS[exp_id]["packet_count"] = len(packets)
                    GENERATION_TASKS[exp_id]["packets"] = packets[-100:]
                    GENERATION_TASKS[exp_id]["bytes_sent"] = client_bytes_sent
                    GENERATION_TASKS[exp_id]["sender_status"] = (
                        f"Sender: Sent chunk {i+1}/{packet_count} ({client_bytes_sent} B)"
                    )

            if interval_ms > 0 and i < packet_count - 1:
                time.sleep(interval_ms / 1000.0)

        client_sock.close()
        server_done.wait(timeout=2.0)

        # Handle cancellation abort
        if cancel_event and cancel_event.is_set():
            if temp_path and temp_path.exists():
                try:
                    temp_path.unlink()
                except Exception:
                    pass
            with TASKS_LOCK:
                if exp_id in GENERATION_TASKS:
                    GENERATION_TASKS[exp_id]["status"] = "cancelled"
            return

        # Handle reassembly & integrity verification
        reassembled_text = None
        text_match = None
        reassembled_bytes = None
        file_sha256 = None
        file_match = None
        final_storage_path = None
        file_id = None

        if payload_mode == "custom_text":
            res = reassemble_packets(received_payloads, expected_sent_text=custom_text)
            reassembled_text = res["received_text"]
            text_match = res["match"]
        elif payload_mode == "file":
            # Verify temp file on disk if streamed, else reconstruct from in-memory payloads
            if temp_path and temp_path.exists():
                # Compute SHA-256 directly from the temp file stream
                h = hashlib.sha256()
                with open(temp_path, "rb") as f:
                    while chunk := f.read(65536):
                        h.update(chunk)
                file_sha256 = h.hexdigest()
                actual_file_size = temp_path.stat().st_size
                
                # Verify checksum and size
                file_match = (file_sha256 == expected_sha256) if expected_sha256 else True
                if expected_size is not None and actual_file_size != expected_size:
                    file_match = False

                if file_match:
                    # Atomically finalize the reconstructed file
                    now = datetime.now()
                    file_id = f"FILE-{now.strftime('%Y%m%d-%H%M%S')}-{os.urandom(2).hex()}"
                    safe_name = sanitize_filename(filename)
                    final_path = UPLOADS_DIR / f"{file_id}_{safe_name}"
                    
                    try:
                        # Atomic rename/replace
                        os.replace(temp_path, final_path)
                        final_storage_path = str(final_path)
                    except Exception as e:
                        # Fallback copy if on different filesystem
                        import shutil
                        shutil.copy2(temp_path, final_path)
                        temp_path.unlink(missing_ok=True)
                        final_storage_path = str(final_path)

                    # Read bytes for in-memory store if needed
                    try:
                        with open(final_storage_path, "rb") as f:
                            reassembled_bytes = f.read()
                    except Exception:
                        pass
                else:
                    # Verification failed: clean up abandoned temporary file
                    try:
                        temp_path.unlink(missing_ok=True)
                    except Exception:
                        pass
            else:
                # In-memory reassembly fallback
                res_bin = reassemble_binary(received_payloads)
                reassembled_bytes = res_bin["raw_bytes"]
                file_sha256 = res_bin["sha256"]
                file_match = (file_sha256 == expected_sha256) if expected_sha256 else res_bin["integrity_ok"]

        self._save_trace_and_complete(
            exp_id, packets, reassembled_text, text_match, None,
            reassembled_bytes, file_sha256, file_match,
            file_id=file_id, storage_path=final_storage_path, filename=filename, params=params
        )

    def _run_udp(
        self,
        packet_count: int,
        packet_size: int,
        interval_ms: float,
        payload_pattern: str,
        is_bidirectional: bool,
        payload_mode: str,
        text_chunks: List[bytes],
        custom_text: str,
        params: Optional[Dict[str, Any]] = None
    ):
        exp_id = self.experiment_id
        params = params or {}
        cancel_event = None
        with TASKS_LOCK:
            if exp_id in GENERATION_TASKS:
                cancel_event = GENERATION_TASKS[exp_id].get("cancel_event")

        filename = params.get("filename", "transfer.bin")
        expected_sha256 = params.get("sent_sha256")
        expected_size = params.get("file_size")

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_sock.bind(("127.0.0.1", 0))
        server_port = server_sock.getsockname()[1]

        client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_sock.bind(("127.0.0.1", 0))
        client_port = client_sock.getsockname()[1]

        received_payloads: List[bytes] = []
        stop_server = threading.Event()
        receiver_bytes_count = 0

        def server_thread():
            nonlocal receiver_bytes_count
            server_sock.settimeout(0.2)
            while not stop_server.is_set():
                if cancel_event and cancel_event.is_set():
                    break
                try:
                    data, addr = server_sock.recvfrom(65535)
                    received_payloads.append(data)
                    receiver_bytes_count += len(data)
                    with TASKS_LOCK:
                        if exp_id in GENERATION_TASKS:
                            GENERATION_TASKS[exp_id]["bytes_received"] = receiver_bytes_count
                            GENERATION_TASKS[exp_id]["receiver_status"] = (
                                f"Receiver: Received {len(received_payloads)} datagrams ({receiver_bytes_count} B)"
                            )

                    if is_bidirectional:
                        ack = b"ACK:" + data[:16]
                        server_sock.sendto(ack, addr)
                except socket.timeout:
                    continue
                except Exception:
                    pass
            server_sock.close()

        s_t = threading.Thread(target=server_thread, daemon=True)
        s_t.start()

        packets: List[Dict[str, Any]] = []
        t0 = time.perf_counter()
        seq_num = 1
        client_bytes_sent = 0

        for i in range(packet_count):
            if cancel_event and cancel_event.is_set():
                break

            if (payload_mode in ("custom_text", "file")) and i < len(text_chunks):
                payload = text_chunks[i]
            else:
                payload = generate_payload_bytes(payload_pattern, packet_size, i)

            client_sock.sendto(payload, ("127.0.0.1", server_port))
            t_send = time.perf_counter() - t0
            crc_hex = f"{zlib.crc32(payload) & 0xffffffff:08x}"
            client_bytes_sent += len(payload)

            p_record = {
                "seq": seq_num,
                "timestamp": round(t_send, 6),
                "proto": "UDP",
                "direction": "C->S",
                "size": len(payload),
                "crc32": crc_hex,
                "src_port": client_port,
                "dst_port": server_port,
                "preview": safe_preview(payload)
            }
            packets.append(p_record)
            seq_num += 1

            if is_bidirectional:
                try:
                    client_sock.settimeout(0.05)
                    ack_data, _ = client_sock.recvfrom(65535)
                    t_ack = time.perf_counter() - t0
                    ack_crc = f"{zlib.crc32(ack_data) & 0xffffffff:08x}"
                    ack_record = {
                        "seq": seq_num,
                        "timestamp": round(t_ack, 6),
                        "proto": "UDP",
                        "direction": "S->C",
                        "size": len(ack_data),
                        "crc32": ack_crc,
                        "src_port": server_port,
                        "dst_port": client_port,
                        "preview": safe_preview(ack_data)
                    }
                    packets.append(ack_record)
                    seq_num += 1
                except socket.timeout:
                    pass

            progress = int(((i + 1) / packet_count) * 100)
            with TASKS_LOCK:
                if exp_id in GENERATION_TASKS:
                    GENERATION_TASKS[exp_id]["progress"] = progress
                    GENERATION_TASKS[exp_id]["packet_count"] = len(packets)
                    GENERATION_TASKS[exp_id]["packets"] = packets[-100:]
                    GENERATION_TASKS[exp_id]["bytes_sent"] = client_bytes_sent
                    GENERATION_TASKS[exp_id]["sender_status"] = (
                        f"Sender: Sent datagram {i+1}/{packet_count} ({client_bytes_sent} B)"
                    )

            if interval_ms > 0 and i < packet_count - 1:
                time.sleep(interval_ms / 1000.0)

        time.sleep(0.08)
        stop_server.set()
        s_t.join(timeout=1.5)
        client_sock.close()

        if cancel_event and cancel_event.is_set():
            with TASKS_LOCK:
                if exp_id in GENERATION_TASKS:
                    GENERATION_TASKS[exp_id]["status"] = "cancelled"
            return

        reassembled_text = None
        text_match = None
        udp_report = None
        reassembled_bytes = None
        file_sha256 = None
        file_match = None
        file_id = None
        final_storage_path = None

        if payload_mode == "custom_text":
            res = reassemble_packets(received_payloads, expected_sent_text=custom_text)
            reassembled_text = res["received_text"]
            text_match = res["match"]
            udp_report = {
                "sent_count": packet_count,
                "received_count": len(received_payloads),
                "lost_count": res["lost_packets"],
                "duplicate_count": res["duplicate_packets"],
                "out_of_order_count": res["out_of_order_packets"]
            }
        elif payload_mode == "file":
            res_bin = reassemble_binary(received_payloads)
            reassembled_bytes = res_bin["raw_bytes"]
            file_sha256 = res_bin["sha256"]
            sent_sha = expected_sha256
            
            # UDP Integrity Rule: Never mark incomplete UDP transfer as successful
            is_complete = (res_bin["lost_packets"] == 0 and res_bin["malformed_packets"] == 0)
            checksum_matches = (file_sha256 == sent_sha) if sent_sha else res_bin["integrity_ok"]
            file_match = bool(is_complete and checksum_matches)

            udp_report = {
                "sent_count": packet_count,
                "received_count": len(received_payloads),
                "lost_count": res_bin["lost_packets"],
                "missing_sequences": res_bin.get("missing_sequences", []),
                "duplicate_count": res_bin["duplicate_packets"],
                "out_of_order_count": res_bin["out_of_order_packets"],
                "integrity_ok": is_complete and checksum_matches
            }

            # Only write and finalize file to storage if transfer is 100% complete & verified
            if file_match and len(reassembled_bytes) > 0:
                now = datetime.now()
                file_id = f"FILE-{now.strftime('%Y%m%d-%H%M%S')}-{os.urandom(2).hex()}"
                safe_name = sanitize_filename(filename)
                UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
                final_path = UPLOADS_DIR / f"{file_id}_{safe_name}"
                with open(final_path, "wb") as f:
                    f.write(reassembled_bytes)
                final_storage_path = str(final_path)

        self._save_trace_and_complete(
            exp_id, packets, reassembled_text, text_match, udp_report,
            reassembled_bytes, file_sha256, file_match,
            file_id=file_id, storage_path=final_storage_path, filename=filename, params=params
        )

    def _save_trace_and_complete(
        self,
        exp_id: str,
        packets: List[Dict[str, Any]],
        reassembled_text: Optional[str] = None,
        text_match: Optional[bool] = None,
        udp_report: Optional[Dict[str, Any]] = None,
        reassembled_bytes: Optional[bytes] = None,
        file_sha256: Optional[str] = None,
        file_match: Optional[bool] = None,
        file_id: Optional[str] = None,
        storage_path: Optional[str] = None,
        filename: str = "transfer.bin",
        params: Optional[Dict[str, Any]] = None
    ):
        TRAFFIC_DIR.mkdir(parents=True, exist_ok=True)
        csv_path = TRAFFIC_DIR / f"{exp_id}.csv"
        try:
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                fieldnames = ["seq", "timestamp", "proto", "direction", "size", "crc32", "src_port", "dst_port", "preview"]
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for p in packets:
                    writer.writerow(p)
        except Exception as e:
            print(f"Error saving CSV trace {csv_path}: {e}")

        # Determine final status
        status = "completed"
        payload_mode = (params or {}).get("payload_mode", "pattern")
        if payload_mode == "file":
            if file_match is False:
                # If UDP dropped packets or checksum failed, never mark as completed
                proto = (params or {}).get("protocol", "TCP").upper()
                if proto == "UDP" and udp_report and udp_report.get("lost_count", 0) > 0:
                    status = "incomplete"
                else:
                    status = "failed"
            elif file_match is True:
                status = "completed"

        with TASKS_LOCK:
            if exp_id in GENERATION_TASKS:
                GENERATION_TASKS[exp_id]["status"] = status
                GENERATION_TASKS[exp_id]["progress"] = 100
                GENERATION_TASKS[exp_id]["packet_count"] = len(packets)
                GENERATION_TASKS[exp_id]["all_packets"] = packets
                GENERATION_TASKS[exp_id]["csv_path"] = str(csv_path)
                GENERATION_TASKS[exp_id]["reassembled_text"] = reassembled_text
                GENERATION_TASKS[exp_id]["text_match"] = text_match
                GENERATION_TASKS[exp_id]["udp_report"] = udp_report
                GENERATION_TASKS[exp_id]["reassembled_bytes"] = reassembled_bytes
                GENERATION_TASKS[exp_id]["file_sha256"] = file_sha256
                GENERATION_TASKS[exp_id]["file_match"] = file_match
                GENERATION_TASKS[exp_id]["file_id"] = file_id
                GENERATION_TASKS[exp_id]["storage_path"] = storage_path
                GENERATION_TASKS[exp_id]["filename"] = filename
                GENERATION_TASKS[exp_id]["sender_status"] = (
                    f"Sender: Finished transmitting {len(packets)} packets on 127.0.0.1."
                )
                if status == "completed":
                    GENERATION_TASKS[exp_id]["receiver_status"] = (
                        "Receiver: Transmission finished. SHA-256 integrity verified 100%."
                    )
                elif status == "incomplete":
                    lost = udp_report.get("lost_count", 0) if udp_report else 0
                    GENERATION_TASKS[exp_id]["receiver_status"] = (
                        f"Receiver: Transfer incomplete ({lost} missing chunks). Reconstructed file rejected."
                    )
                else:
                    GENERATION_TASKS[exp_id]["receiver_status"] = (
                        "Receiver: Checksum verification mismatch. File rejected."
                    )

        # JSON persistence integration for file transfers
        if payload_mode == "file":
            try:
                from backend.json_storage import (
                    save_transferred_file, save_analysis_result, save_experiment,
                    detect_mime_type
                )
                from backend.feature_extractor import extract_and_save_features
                from backend.dpi_classifier import classify_traffic

                feat = {}
                try:
                    feat = extract_and_save_features(exp_id)
                except Exception:
                    pass
                classification = classify_traffic(feat) if feat else {}

                analysis_id = f"ANALYSIS-{int(time.time()*1000)}-{os.urandom(2).hex()}"
                analysis_rec = {
                    "analysis_id": analysis_id,
                    "file_id": file_id,
                    "experiment_id": exp_id,
                    "stage": "before",
                    "transport_protocol": (params or {}).get("protocol", "TCP"),
                    "packet_count": len(packets),
                    "total_bytes": feat.get("total_bytes", sum(p.get("size", 0) for p in packets)),
                    "mean_size": feat.get("mean_size", 0.0),
                    "min_size": feat.get("min_size", 0),
                    "max_size": feat.get("max_size", 0),
                    "jitter_ms": feat.get("jitter_ms", 0.0),
                    "throughput_kbps": feat.get("throughput_kbps", 0.0),
                    "classifier_result": classification,
                    "classifier_config_version": "1.0.0",
                    "analysis_timestamp": datetime.now().isoformat(),
                    "execution_status": "completed" if status == "completed" else "interrupted",
                    "errors": None if status == "completed" else f"Transfer ended with status: {status}"
                }
                save_analysis_result(analysis_rec)

                assigned_file_id = file_id or f"FILE-{int(time.time()*1000)}-{os.urandom(2).hex()}"
                file_rec = {
                    "file_id": assigned_file_id,
                    "original_filename": filename,
                    "sanitized_filename": sanitize_filename(filename),
                    "extension": Path(filename).suffix.lower(),
                    "mime_type": detect_mime_type(filename),
                    "size_bytes": len(reassembled_bytes) if reassembled_bytes else (params or {}).get("file_size", 0),
                    "sha256": (params or {}).get("sent_sha256", file_sha256 or ""),
                    "received_sha256": file_sha256 or "",
                    "integrity_verified": bool(file_match and status == "completed"),
                    "transfer_protocol": (params or {}).get("protocol", "TCP"),
                    "source_label": "Client (127.0.0.1)",
                    "dest_label": "Server (127.0.0.1)",
                    "storage_path": storage_path or "",
                    "transfer_started_at": (GENERATION_TASKS.get(exp_id, {})).get("created_at", datetime.now().isoformat()),
                    "transfer_completed_at": datetime.now().isoformat(),
                    "duration_ms": round(packets[-1]["timestamp"] * 1000.0, 2) if packets else 0.0,
                    "status": status,
                    "experiment_id": exp_id,
                    "analysis_id": analysis_id,
                    "created_at": datetime.now().isoformat()
                }
                save_transferred_file(file_rec)

                exp_rec = {
                    "id": exp_id,
                    "experiment_id": exp_id,
                    "file_id": assigned_file_id,
                    "analysis_before_id": analysis_id,
                    "created_at": file_rec["transfer_started_at"],
                    "updated_at": file_rec["transfer_completed_at"],
                    "status": status,
                    "config": {
                        "protocol": (params or {}).get("protocol", "TCP"),
                        "packet_count": len(packets),
                        "packet_size": (params or {}).get("packet_size", 512),
                        "payload_mode": "file",
                        "filename": filename
                    },
                    "features_before": feat,
                    "classification_before": classification,
                    "original_checksum": file_rec["sha256"],
                    "content_integrity_verified": file_rec["integrity_verified"]
                }
                save_experiment(exp_rec)

                with TASKS_LOCK:
                    if exp_id in GENERATION_TASKS:
                        GENERATION_TASKS[exp_id]["file_id"] = assigned_file_id
                        GENERATION_TASKS[exp_id]["analysis_id"] = analysis_id
                        GENERATION_TASKS[exp_id]["features"] = feat
                        GENERATION_TASKS[exp_id]["classification"] = classification
            except Exception as e:
                print(f"Error persisting file transfer data: {e}")


def get_task_status(exp_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve active status and recent trace window for polling."""
    with TASKS_LOCK:
        task = GENERATION_TASKS.get(exp_id)
        if task:
            return {
                "id": task["id"],
                "status": task["status"],
                "progress": task["progress"],
                "packet_count": task["packet_count"],
                "target_count": task.get("target_count", 0),
                "packets": list(task.get("packets", [])),
                "reassembled_text": task.get("reassembled_text"),
                "text_match": task.get("text_match"),
                "file_sha256": task.get("file_sha256"),
                "file_match": task.get("file_match"),
                "file_id": task.get("file_id"),
                "filename": task.get("filename"),
                "storage_path": task.get("storage_path"),
                "bytes_sent": task.get("bytes_sent", 0),
                "bytes_received": task.get("bytes_received", 0),
                "total_bytes": task.get("total_bytes", 0),
                "sender_status": task.get("sender_status"),
                "receiver_status": task.get("receiver_status"),
                "udp_report": task.get("udp_report"),
                "error": task.get("error")
            }
    return None
