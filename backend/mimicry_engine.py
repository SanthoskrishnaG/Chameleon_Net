"""
Protocol Mimicry Engine.
Transforms traffic features toward a target educational profile:
- Size padding / trimming
- Timing reshaping with controlled jitter
- Burst injection and inter-burst spacing
- Transmits transformed traffic over real 127.0.0.1 localhost sockets
- Proves custom text preservation through automated padding stripping
- Measures true network overhead (extra bytes %, added delay %, throughput change)
"""

import os
import csv
import zlib
import time
import socket
import struct
import random
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from backend.config import TRAFFIC_DIR, FEATURES_DIR, is_loopback
from backend.profiles import get_profile
from backend.text_payload import (
    HEADER_MAGIC, HEADER_FORMAT, HEADER_SIZE, FLAG_PADDED,
    reassemble_packets
)
from backend.feature_extractor import (
    load_packets_from_csv, extract_features_from_packets,
    extract_and_save_features, load_saved_features
)


def safe_preview(data: bytes, max_len: int = 20) -> str:
    """Safe ASCII preview of bytes."""
    chars = []
    for b in data[:max_len]:
        if 32 <= b <= 126:
            chars.append(chr(b))
        else:
            chars.append(".")
    return "".join(chars)


def reshape_packet_size(
    raw_payload: bytes,
    target_size: int,
    is_text: bool
) -> bytes:
    """
    Transform packet size towards target_size.
    Preserves text framing headers so padding can be stripped transparently upon reassembly.
    """
    target_size = max(24, min(1460, target_size))
    
    if is_text and len(raw_payload) >= HEADER_SIZE and raw_payload.startswith(HEADER_MAGIC):
        header = raw_payload[:HEADER_SIZE]
        magic, seq, total_chunks, data_len, flags = struct.unpack(HEADER_FORMAT, header)
        pure_data = raw_payload[HEADER_SIZE:HEADER_SIZE + data_len]
        
        # If target size is larger than header + data_len, pad
        min_needed = HEADER_SIZE + data_len
        if target_size > min_needed:
            pad_len = target_size - min_needed
            padding = os.urandom(pad_len)
            new_flags = flags | FLAG_PADDED
            new_header = struct.pack(HEADER_FORMAT, HEADER_MAGIC, seq, total_chunks, data_len, new_flags)
            return new_header + pure_data + padding
        else:
            # Cannot shrink below header + data_len without fragmenting data
            return raw_payload
    else:
        # Generic payload pattern
        curr_len = len(raw_payload)
        if curr_len < target_size:
            return raw_payload + os.urandom(target_size - curr_len)
        elif curr_len > target_size:
            return raw_payload[:target_size]
        else:
            return raw_payload


class MimicryEngine:
    """
    Transforms and re-transmits traffic traces across localhost loopback.
    """

    def __init__(self, experiment_id: str):
        self.experiment_id = experiment_id
        self.host = "127.0.0.1"
        if not is_loopback(self.host):
            raise ValueError("Safety violation: Mimicry execution requires 127.0.0.1 loopback.")

    def apply_mimicry(
        self,
        target_profile_id: str,
        toggles: Optional[Dict[str, bool]] = None,
        custom_jitter_ms: Optional[float] = None,
        custom_burst_len: Optional[float] = None,
        transport_mode: str = "keep_original",
        original_text: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes end-to-end mimicry transformation, socket re-transmission, and overhead accounting.
        """
        toggles = toggles or {"padding": True, "timing": True, "burst": True}
        use_padding = bool(toggles.get("padding", True))
        use_timing = bool(toggles.get("timing", True))
        use_burst = bool(toggles.get("burst", True))

        target_prof = get_profile(target_profile_id)
        original_csv = TRAFFIC_DIR / f"{self.experiment_id}.csv"
        original_packets = load_packets_from_csv(original_csv)

        if not original_packets:
            raise ValueError(f"No original packets found for experiment {self.experiment_id}")

        source_proto = original_packets[0]["proto"].upper()
        target_proto = target_prof["transport"].upper()
        transport_mismatch = (source_proto != target_proto)

        # Decide transmission protocol
        if transport_mode == "convert_transport":
            transmit_proto = target_proto
            limitation_report = None
        else:
            transmit_proto = source_proto
            if transport_mismatch:
                limitation_report = (
                    f"Honest Limitation: Source traffic is {source_proto}, while target '{target_prof['name']}' "
                    f"is defined on {target_proto}. In 'keep_original' mode, rule 5 (Transport Match) will "
                    f"detect the mismatch, capping mimicry confidence."
                )
            else:
                limitation_report = None

        # Determine if payload is framed custom text
        is_text_mode = False
        sample_payload_bytes = original_packets[0].get("preview", "").encode("ascii", errors="replace")
        # Check first packet by loading from disk or checking preview
        if original_text is not None:
            is_text_mode = True

        # Prepare transformed payloads
        target_size = int(target_prof["target_size"])
        transformed_payloads: List[bytes] = []

        for p in original_packets:
            # Reconstruct original bytes from size and preview or dummy bytes
            p_size = int(p["size"])
            # If text mode, check if we have the text chunks
            p_bytes = bytes([(i % 256) for i in range(p_size)])
            
            if use_padding:
                new_p = reshape_packet_size(p_bytes, target_size, is_text_mode)
            else:
                new_p = p_bytes
            transformed_payloads.append(new_p)

        # If original text was supplied, re-chunk it directly to target_size to ensure valid framed packets
        if is_text_mode and original_text:
            from backend.text_payload import chunk_text
            chunk_size = target_size if use_padding else int(original_packets[0]["size"])
            transformed_payloads = chunk_text(original_text, chunk_size, pad_last=use_padding)

        # Calculate inter-packet sleep delays
        target_ipt_ms = float(target_prof["target_ipt_ms"])
        target_jitter_ms = float(custom_jitter_ms if custom_jitter_ms is not None else target_prof["target_jitter_ms"])
        target_burst_len = int(custom_burst_len if custom_burst_len is not None else target_prof.get("target_burst_length", 2))

        delays_sec: List[float] = []
        num_packets = len(transformed_payloads)

        for i in range(1, num_packets):
            if use_burst and target_burst_len > 1:
                if (i % target_burst_len) != 0:
                    # Inside burst: very rapid (< 15ms)
                    d_ms = random.uniform(3.0, min(14.0, target_ipt_ms * 0.4))
                else:
                    # Inter-burst gap
                    d_ms = max(25.0, target_ipt_ms * target_burst_len * 1.3)
            elif use_timing:
                d_ms = target_ipt_ms + random.uniform(-target_jitter_ms, target_jitter_ms)
                d_ms = max(1.0, d_ms)
            else:
                # Default minimal delay
                d_ms = 10.0
            delays_sec.append(d_ms / 1000.0)

        # REAL Socket Re-transmission on 127.0.0.1
        mimic_packets, received_raw_bytes = self._execute_socket_transmission(
            transmit_proto, transformed_payloads, delays_sec
        )

        # Save transformed trace CSV
        mimic_csv = TRAFFIC_DIR / f"{self.experiment_id}_mimic.csv"
        with open(mimic_csv, "w", newline="", encoding="utf-8") as f:
            fieldnames = ["seq", "timestamp", "proto", "direction", "size", "crc32", "src_port", "dst_port", "preview"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for p in mimic_packets:
                writer.writerow(p)

        # Extract transformed features
        transformed_features = extract_and_save_features(self.experiment_id, suffix="_mimic")
        mimicry_exp_id = f"{self.experiment_id}_mimic"
        transformed_features["experiment_id"] = self.experiment_id
        transformed_features["original_experiment_id"] = self.experiment_id
        transformed_features["mimicry_experiment_id"] = mimicry_exp_id
        transformed_features["parent_experiment_id"] = self.experiment_id
        transformed_features["comparison_id"] = self.experiment_id

        # Update saved mimic feature json with linking IDs
        try:
            feat_path = FEATURES_DIR / f"{self.experiment_id}_mimic.json"
            if feat_path.exists():
                with open(feat_path, "w", encoding="utf-8") as f:
                    json.dump(transformed_features, f, indent=2)
        except Exception:
            pass

        # Load or extract original features
        original_features = load_saved_features(self.experiment_id)
        if not original_features:
            original_features = extract_and_save_features(self.experiment_id)

        # Verify text preservation if applicable
        text_preserved = None
        reassembled_text = None
        if is_text_mode and original_text:
            res = reassemble_packets(received_raw_bytes, expected_sent_text=original_text)
            reassembled_text = res["received_text"]
            text_preserved = res["match"]

        # Calculate Overhead
        orig_bytes = original_features["total_bytes"]
        new_bytes = transformed_features["total_bytes"]
        extra_bytes_pct = round(((new_bytes - orig_bytes) / max(1, orig_bytes)) * 100.0, 1)

        orig_dur = original_features["duration"]
        new_dur = transformed_features["duration"]
        added_delay_pct = round(((new_dur - orig_dur) / max(0.001, orig_dur)) * 100.0, 1)

        orig_bps = original_features["bytes_per_sec"]
        new_bps = transformed_features["bytes_per_sec"]
        throughput_chg_pct = round(((new_bps - orig_bps) / max(1.0, orig_bps)) * 100.0, 1)

        overhead = {
            "original_bytes": orig_bytes,
            "transformed_bytes": new_bytes,
            "extra_bytes_percent": extra_bytes_pct,
            "original_duration_sec": orig_dur,
            "transformed_duration_sec": new_dur,
            "added_delay_percent": added_delay_pct,
            "original_throughput_bps": orig_bps,
            "transformed_throughput_bps": new_bps,
            "throughput_change_percent": throughput_chg_pct
        }

        return {
            "experiment_id": self.experiment_id,
            "original_experiment_id": self.experiment_id,
            "mimicry_experiment_id": mimicry_exp_id,
            "parent_experiment_id": self.experiment_id,
            "comparison_id": self.experiment_id,
            "target_profile": target_prof,
            "toggles": toggles,
            "transport_mode": transport_mode,
            "limitation_report": limitation_report,
            "overhead": overhead,
            "text_preserved": text_preserved,
            "reassembled_text": reassembled_text,
            "transformed_features": transformed_features,
            "packet_count": len(mimic_packets)
        }

    def _execute_socket_transmission(
        self,
        proto: str,
        payloads: List[bytes],
        delays_sec: List[float]
    ) -> Tuple[List[Dict[str, Any]], List[bytes]]:
        """
        Transmits payload list over real localhost socket.
        """
        received_chunks: List[bytes] = []

        if proto == "TCP":
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            server_sock.bind(("127.0.0.1", 0))
            server_sock.listen(1)
            server_port = server_sock.getsockname()[1]
            server_ready = threading.Event()
            server_done = threading.Event()

            def s_worker():
                server_ready.set()
                try:
                    conn, _ = server_sock.accept()
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    while True:
                        raw_len = conn.recv(4)
                        if not raw_len or len(raw_len) < 4:
                            break
                        msg_len = struct.unpack("!I", raw_len)[0]
                        data = bytearray()
                        while len(data) < msg_len:
                            chunk = conn.recv(min(4096, msg_len - len(data)))
                            if not chunk:
                                break
                            data.extend(chunk)
                        if len(data) == msg_len:
                            received_chunks.append(bytes(data))
                    conn.close()
                except Exception:
                    pass
                finally:
                    server_sock.close()
                    server_done.set()

            t = threading.Thread(target=s_worker, daemon=True)
            t.start()
            server_ready.wait()

            client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            client_sock.connect(("127.0.0.1", server_port))
            client_port = client_sock.getsockname()[1]

            packets: List[Dict[str, Any]] = []
            t0 = time.perf_counter()

            for i, p in enumerate(payloads):
                client_sock.sendall(struct.pack("!I", len(p)) + p)
                t_send = time.perf_counter() - t0
                packets.append({
                    "seq": i + 1,
                    "timestamp": round(t_send, 6),
                    "proto": "TCP",
                    "direction": "C->S",
                    "size": len(p),
                    "crc32": f"{zlib.crc32(p) & 0xffffffff:08x}",
                    "src_port": client_port,
                    "dst_port": server_port,
                    "preview": safe_preview(p)
                })
                if i < len(delays_sec):
                    time.sleep(delays_sec[i])

            client_sock.close()
            server_done.wait(timeout=2.0)
            return packets, received_chunks

        else:
            # UDP
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server_sock.bind(("127.0.0.1", 0))
            server_port = server_sock.getsockname()[1]

            client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_sock.bind(("127.0.0.1", 0))
            client_port = client_sock.getsockname()[1]

            stop_s = threading.Event()

            def udp_s():
                server_sock.settimeout(0.2)
                while not stop_s.is_set():
                    try:
                        data, _ = server_sock.recvfrom(65535)
                        received_chunks.append(data)
                    except socket.timeout:
                        continue
                    except Exception:
                        break
                server_sock.close()

            t = threading.Thread(target=udp_s, daemon=True)
            t.start()

            packets = []
            t0 = time.perf_counter()

            for i, p in enumerate(payloads):
                client_sock.sendto(p, ("127.0.0.1", server_port))
                t_send = time.perf_counter() - t0
                packets.append({
                    "seq": i + 1,
                    "timestamp": round(t_send, 6),
                    "proto": "UDP",
                    "direction": "C->S",
                    "size": len(p),
                    "crc32": f"{zlib.crc32(p) & 0xffffffff:08x}",
                    "src_port": client_port,
                    "dst_port": server_port,
                    "preview": safe_preview(p)
                })
                if i < len(delays_sec):
                    time.sleep(delays_sec[i])

            time.sleep(0.05)
            stop_s.set()
            t.join(timeout=1.0)
            client_sock.close()
            return packets, received_chunks
