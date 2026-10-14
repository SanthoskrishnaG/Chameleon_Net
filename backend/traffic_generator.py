"""
Socket-based Traffic Generator for 127.0.0.1 Loopback.
Executes real TCP/UDP transmissions with high-precision timestamping,
live trace streaming, CRC32 checksumming, and bidirectional echo support.
"""

import os
import csv
import zlib
import time
import socket
import struct
import string
import random
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional

from backend.config import TRAFFIC_DIR, is_loopback
from backend.text_payload import chunk_text, reassemble_packets, HEADER_SIZE

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


class TrafficGenerator:
    """
    Manages live socket transmissions across 127.0.0.1.
    Strictly forbids non-loopback addresses.
    """

    def __init__(self, experiment_id: Optional[str] = None):
        self.experiment_id = experiment_id or generate_experiment_id()
        self.host = "127.0.0.1"
        if not is_loopback(self.host):
            raise ValueError(f"Safety violation: Host {self.host} is not an authorized loopback address.")

    def run_generation_async(self, params: Dict[str, Any]) -> str:
        """Launch transmission in a managed background thread."""
        exp_id = self.experiment_id
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
                "udp_report": None,
                "created_at": datetime.now().isoformat(),
                "params": params
            }

        thread = threading.Thread(target=self._worker, args=(params,), daemon=True)
        thread.start()
        return exp_id

    def _worker(self, params: Dict[str, Any]):
        exp_id = self.experiment_id
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

            is_bidirectional = (direction == "bidirectional")

            # Determine payloads to send
            text_chunks: List[bytes] = []
            if payload_mode == "custom_text":
                text_chunks = chunk_text(custom_text, packet_size, pad_last=pad_last)
                packet_count = len(text_chunks)
                with TASKS_LOCK:
                    if exp_id in GENERATION_TASKS:
                        GENERATION_TASKS[exp_id]["target_count"] = packet_count

            if proto == "TCP":
                self._run_tcp(
                    packet_count=packet_count,
                    packet_size=packet_size,
                    interval_ms=interval_ms,
                    payload_pattern=payload_pattern,
                    is_bidirectional=is_bidirectional,
                    payload_mode=payload_mode,
                    text_chunks=text_chunks,
                    custom_text=custom_text
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
                    custom_text=custom_text
                )

        except Exception as e:
            with TASKS_LOCK:
                if exp_id in GENERATION_TASKS:
                    GENERATION_TASKS[exp_id]["status"] = "failed"
                    GENERATION_TASKS[exp_id]["error"] = str(e)

    def _run_tcp(
        self,
        packet_count: int,
        packet_size: int,
        interval_ms: float,
        payload_pattern: str,
        is_bidirectional: bool,
        payload_mode: str,
        text_chunks: List[bytes],
        custom_text: str
    ):
        exp_id = self.experiment_id
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        server_port = server_sock.getsockname()[1]

        received_payloads: List[bytes] = []
        server_ready = threading.Event()
        server_done = threading.Event()

        def server_thread():
            server_ready.set()
            try:
                conn, _ = server_sock.accept()
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                while True:
                    # Read 4-byte framing prefix
                    raw_len = conn.recv(4)
                    if not raw_len or len(raw_len) < 4:
                        break
                    msg_len = struct.unpack("!I", raw_len)[0]
                    # Read full payload
                    data = bytearray()
                    while len(data) < msg_len:
                        chunk = conn.recv(min(4096, msg_len - len(data)))
                        if not chunk:
                            break
                        data.extend(chunk)
                    if len(data) == msg_len:
                        received_payloads.append(bytes(data))
                        if is_bidirectional:
                            # Echo response
                            ack = b"ACK:" + bytes(data[:16])
                            conn.sendall(struct.pack("!I", len(ack)) + ack)
                conn.close()
            except Exception:
                pass
            finally:
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

        packets: List[Dict[str, Any]] = []
        t0 = time.perf_counter()
        seq_num = 1

        for i in range(packet_count):
            if payload_mode == "custom_text" and i < len(text_chunks):
                payload = text_chunks[i]
            else:
                payload = generate_payload_bytes(payload_pattern, packet_size, i)

            # Send framed packet
            client_sock.sendall(struct.pack("!I", len(payload)) + payload)
            t_send = time.perf_counter() - t0
            crc_hex = f"{zlib.crc32(payload) & 0xffffffff:08x}"
            
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
                # Receive echo ACK
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

            # Update live state
            progress = int(((i + 1) / packet_count) * 100)
            with TASKS_LOCK:
                if exp_id in GENERATION_TASKS:
                    GENERATION_TASKS[exp_id]["progress"] = progress
                    GENERATION_TASKS[exp_id]["packet_count"] = len(packets)
                    GENERATION_TASKS[exp_id]["packets"] = packets[-100:]  # latest 100 for trace window

            if interval_ms > 0 and i < packet_count - 1:
                time.sleep(interval_ms / 1000.0)

        client_sock.close()
        server_done.wait(timeout=2.0)

        # Handle custom text reassembly
        reassembled_text = None
        text_match = None
        if payload_mode == "custom_text":
            res = reassemble_packets(received_payloads, expected_sent_text=custom_text)
            reassembled_text = res["received_text"]
            text_match = res["match"]

        self._save_trace_and_complete(exp_id, packets, reassembled_text, text_match)

    def _run_udp(
        self,
        packet_count: int,
        packet_size: int,
        interval_ms: float,
        payload_pattern: str,
        is_bidirectional: bool,
        payload_mode: str,
        text_chunks: List[bytes],
        custom_text: str
    ):
        exp_id = self.experiment_id
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_sock.bind(("127.0.0.1", 0))
        server_port = server_sock.getsockname()[1]

        client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_sock.bind(("127.0.0.1", 0))
        client_port = client_sock.getsockname()[1]

        received_payloads: List[bytes] = []
        stop_server = threading.Event()

        def server_thread():
            server_sock.settimeout(0.2)
            while not stop_server.is_set():
                try:
                    data, addr = server_sock.recvfrom(65535)
                    received_payloads.append(data)
                    if is_bidirectional:
                        ack = b"ACK:" + data[:16]
                        server_sock.sendto(ack, addr)
                except socket.timeout:
                    continue
                except Exception:
                    break
            server_sock.close()

        s_t = threading.Thread(target=server_thread, daemon=True)
        s_t.start()

        packets: List[Dict[str, Any]] = []
        t0 = time.perf_counter()
        seq_num = 1

        for i in range(packet_count):
            if payload_mode == "custom_text" and i < len(text_chunks):
                payload = text_chunks[i]
            else:
                payload = generate_payload_bytes(payload_pattern, packet_size, i)

            client_sock.sendto(payload, ("127.0.0.1", server_port))
            t_send = time.perf_counter() - t0
            crc_hex = f"{zlib.crc32(payload) & 0xffffffff:08x}"

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

            if interval_ms > 0 and i < packet_count - 1:
                time.sleep(interval_ms / 1000.0)

        time.sleep(0.05)  # Allow trailing packets to arrive
        stop_server.set()
        s_t.join(timeout=1.0)
        client_sock.close()

        reassembled_text = None
        text_match = None
        udp_report = None
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

        self._save_trace_and_complete(exp_id, packets, reassembled_text, text_match, udp_report)

    def _save_trace_and_complete(
        self,
        exp_id: str,
        packets: List[Dict[str, Any]],
        reassembled_text: Optional[str] = None,
        text_match: Optional[bool] = None,
        udp_report: Optional[Dict[str, Any]] = None
    ):
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

        with TASKS_LOCK:
            if exp_id in GENERATION_TASKS:
                GENERATION_TASKS[exp_id]["status"] = "completed"
                GENERATION_TASKS[exp_id]["progress"] = 100
                GENERATION_TASKS[exp_id]["packet_count"] = len(packets)
                GENERATION_TASKS[exp_id]["all_packets"] = packets
                GENERATION_TASKS[exp_id]["csv_path"] = str(csv_path)
                GENERATION_TASKS[exp_id]["reassembled_text"] = reassembled_text
                GENERATION_TASKS[exp_id]["text_match"] = text_match
                GENERATION_TASKS[exp_id]["udp_report"] = udp_report


def get_task_status(exp_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve active status and recent trace window for polling."""
    with TASKS_LOCK:
        task = GENERATION_TASKS.get(exp_id)
        if task:
            # Return copy with recent packets
            return {
                "id": task["id"],
                "status": task["status"],
                "progress": task["progress"],
                "packet_count": task["packet_count"],
                "target_count": task.get("target_count", 0),
                "packets": list(task.get("packets", [])),
                "reassembled_text": task.get("reassembled_text"),
                "text_match": task.get("text_match"),
                "udp_report": task.get("udp_report"),
                "error": task.get("error")
            }
    return None
