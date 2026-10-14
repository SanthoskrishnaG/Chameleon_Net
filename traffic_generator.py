"""
Traffic Generator Module
Generates synthetic and controlled TCP/UDP network traffic for experimentation.
Simulates baseline traffic types: Plaintext Chat/Command, Bulk Data Transfer, Periodic Heartbeat/Beacon, Video Streaming.
"""

import socket
import threading
import time
import random
import json
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class PacketRecord:
    timestamp: float
    direction: str  # "C->S" (Client to Server) or "S->C" (Server to Client)
    protocol: str   # "TCP" or "UDP"
    size: int
    payload: bytes
    entropy: float = 0.0

@dataclass
class FlowRecord:
    flow_id: str
    traffic_type: str
    transport_protocol: str
    packets: List[PacketRecord] = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0

class TrafficGenerator:
    """
    Controlled socket-based traffic generator operating on localhost loopback.
    Supports generation of distinct baseline network application profiles.
    """
    
    TRAFFIC_PROFILES = {
        "plaintext_shell": {
            "name": "Plaintext Remote Shell / Commands",
            "transport": "TCP",
            "description": "Small, sporadic command packets with low entropy and variable human-typing delay.",
            "messages": [
                b"whoami\n",
                b"uname -a\n",
                b"cat /etc/passwd\n",
                b"ls -la /var/log\n",
                b"ps aux | grep root\n",
                b"netstat -tulnp\n"
            ]
        },
        "bulk_data_transfer": {
            "name": "Unencrypted Bulk Data File Transfer",
            "transport": "TCP",
            "description": "Large contiguous packet bursts hitting standard MTU (1000-1460 bytes) with repetitive text/log patterns.",
            "chunk_sizes": [1024, 1400, 1460, 1200, 1350]
        },
        "periodic_beacon": {
            "name": "Periodic IoT / Telemetry Beacon",
            "transport": "UDP",
            "description": "Fixed interval, constant small packet size (48-64 bytes) telemetry bursts.",
            "interval": 0.15,
            "packet_count": 8
        },
        "media_stream": {
            "name": "Real-time Video / Audio UDP Stream",
            "transport": "UDP",
            "description": "High frequency UDP datagrams with variable sizes and bursty cadence.",
            "packet_count": 12
        }
    }

    def __init__(self, host: str = "127.0.0.1", port: int = 9998):
        self.host = host
        self.port = port

    def generate_flow(self, traffic_type: str = "plaintext_shell") -> FlowRecord:
        """
        Generates simulated packets and transmits them over real loopback sockets
        to record realistic network timing, packet sizes, and socket behavior.
        """
        if traffic_type not in self.TRAFFIC_PROFILES:
            traffic_type = "plaintext_shell"

        profile = self.TRAFFIC_PROFILES[traffic_type]
        transport = profile.get("transport", "TCP")
        flow_id = f"flow_{int(time.time()*1000)}_{random.randint(100, 999)}"
        packets: List[PacketRecord] = []
        start_time = time.time()

        # Run local socket exchange to capture true socket timing
        if transport == "TCP":
            packets = self._run_tcp_exchange(traffic_type, profile)
        else:
            packets = self._run_udp_exchange(traffic_type, profile)

        end_time = time.time()
        if not packets:
            # Fallback synthetic generation if socket fails
            packets = self._generate_synthetic_packets(traffic_type, profile)

        return FlowRecord(
            flow_id=flow_id,
            traffic_type=traffic_type,
            transport_protocol=transport,
            packets=packets,
            start_time=start_time,
            end_time=end_time
        )

    def _run_tcp_exchange(self, traffic_type: str, profile: Dict[str, Any]) -> List[PacketRecord]:
        packets = []
        received_packets = []
        server_ready = threading.Event()

        # Server thread
        def tcp_server():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    s.bind((self.host, self.port))
                    s.listen(1)
                    s.settimeout(2.5)
                    server_ready.set()
                    conn, _ = s.accept()
                    with conn:
                        conn.settimeout(2.5)
                        while True:
                            data = conn.recv(4096)
                            if not data:
                                break
                            recv_time = time.time()
                            received_packets.append(PacketRecord(
                                timestamp=recv_time,
                                direction="C->S",
                                protocol="TCP",
                                size=len(data),
                                payload=data
                            ))
                            # Send server acknowledgement / reply
                            ack = b"OK\n" if b"\n" in data else b"ACK:" + data[:16]
                            conn.sendall(ack)
                except Exception:
                    pass

        server_th = threading.Thread(target=tcp_server, daemon=True)
        server_th.start()
        server_ready.wait(timeout=1.0)

        # Client transmission
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.settimeout(2.0)
                client.connect((self.host, self.port))

                if traffic_type == "plaintext_shell":
                    for cmd in profile["messages"]:
                        t_send = time.time()
                        client.sendall(cmd)
                        time.sleep(random.uniform(0.04, 0.12))
                        try:
                            resp = client.recv(1024)
                            packets.append(PacketRecord(
                                timestamp=time.time(),
                                direction="S->C",
                                protocol="TCP",
                                size=len(resp),
                                payload=resp
                            ))
                        except Exception:
                            pass
                elif traffic_type == "bulk_data_transfer":
                    for sz in profile["chunk_sizes"]:
                        # Synthetic log data chunk
                        chunk = (f"LOG_ENTRY [{time.time()}] SYS_DATA: " + "A" * (sz - 40)).encode()
                        client.sendall(chunk)
                        time.sleep(random.uniform(0.01, 0.03))
                        try:
                            resp = client.recv(1024)
                            packets.append(PacketRecord(
                                timestamp=time.time(),
                                direction="S->C",
                                protocol="TCP",
                                size=len(resp),
                                payload=resp
                            ))
                        except Exception:
                            pass
        except Exception:
            pass

        server_th.join(timeout=1.0)
        # Combine client and server records sorted by timestamp
        combined = received_packets + packets
        combined.sort(key=lambda p: p.timestamp)
        return combined if combined else self._generate_synthetic_packets(traffic_type, profile)

    def _run_udp_exchange(self, traffic_type: str, profile: Dict[str, Any]) -> List[PacketRecord]:
        packets = []
        server_port = self.port + 1
        stop_server = threading.Event()

        def udp_server():
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    s.bind((self.host, server_port))
                    s.settimeout(1.5)
                    while not stop_server.is_set():
                        try:
                            data, addr = s.recvfrom(4096)
                            packets.append(PacketRecord(
                                timestamp=time.time(),
                                direction="C->S",
                                protocol="UDP",
                                size=len(data),
                                payload=data
                            ))
                        except socket.timeout:
                            continue
                except Exception:
                    pass

        srv_th = threading.Thread(target=udp_server, daemon=True)
        srv_th.start()
        time.sleep(0.05)

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                if traffic_type == "periodic_beacon":
                    for i in range(profile.get("packet_count", 6)):
                        payload = f"BEACON_HEARTBEAT_ID={i:04d}_TS={time.time()}".encode()
                        client.sendto(payload, (self.host, server_port))
                        time.sleep(profile.get("interval", 0.1))
                else:  # media_stream
                    for i in range(profile.get("packet_count", 10)):
                        sz = random.choice([512, 768, 1024, 1200, 320])
                        payload = b"\x80\x60" + (i).to_bytes(2, "big") + bytes([random.randint(0, 255) for _ in range(sz)])
                        client.sendto(payload, (self.host, server_port))
                        time.sleep(random.uniform(0.015, 0.04))
        except Exception:
            pass

        time.sleep(0.1)
        stop_server.set()
        srv_th.join(timeout=1.0)
        return packets if packets else self._generate_synthetic_packets(traffic_type, profile)

    def _generate_synthetic_packets(self, traffic_type: str, profile: Dict[str, Any]) -> List[PacketRecord]:
        """High-fidelity fallback generator in case socket bind encounters sandbox restrictions."""
        packets = []
        base_t = time.time()
        if traffic_type == "plaintext_shell":
            for i, cmd in enumerate(profile.get("messages", [b"ls\n", b"cat /etc/issue\n"])):
                base_t += random.uniform(0.1, 0.3)
                packets.append(PacketRecord(timestamp=base_t, direction="C->S", protocol="TCP", size=len(cmd), payload=cmd))
                base_t += random.uniform(0.02, 0.05)
                ack = b"OK\n"
                packets.append(PacketRecord(timestamp=base_t, direction="S->C", protocol="TCP", size=len(ack), payload=ack))
        elif traffic_type == "bulk_data_transfer":
            for sz in profile.get("chunk_sizes", [1024, 1460, 1460, 1024]):
                base_t += random.uniform(0.01, 0.03)
                payload = b"TRANSFER_BLOCK_" + (b"X" * (sz - 15))
                packets.append(PacketRecord(timestamp=base_t, direction="C->S", protocol="TCP", size=sz, payload=payload))
        else:
            for i in range(6):
                base_t += 0.1
                payload = f"BEACON_ID={i:03d}".encode()
                packets.append(PacketRecord(timestamp=base_t, direction="C->S", protocol="UDP", size=len(payload), payload=payload))
        return packets
