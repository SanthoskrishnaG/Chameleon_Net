"""
Protocol Mimicry Engine Module
Applies controlled transformations to network traffic characteristics to disguise
arbitrary source traffic as target protocols (e.g., HTTPS/TLS, DNS Query, HTTP/1.1).

Transformations:
1. Header Synthesization & Framing (L7 magic bytes, protocol headers)
2. Packet Sizing & Padding (quantization, target profile fitting)
3. Timing Jitter & Scheduling (delay shaping, burst smoothing)
4. Entropy Shaping (randomization padding to emulate ciphertext or encoding to emulate plaintext)
"""

import time
import random
import os
import struct
from typing import List, Dict, Any, Optional
from traffic_generator import FlowRecord, PacketRecord

class ProtocolMimicryEngine:
    """
    Transforms arbitrary input traffic flows into synthetic profiles matching
    target protocols to study evasion against DPI and firewall classifiers.
    """

    TARGET_PROTOCOLS = {
        "tls_https": {
            "name": "TLS 1.3 / HTTPS Mimicry",
            "description": "Encapsulates data in TLS Record layer frames (0x16 Handshake, 0x17 AppData), pads with high-entropy bytes to mimic AES-GCM ciphertext (~7.8 bits/byte), and shapes packet lengths to TLS MTU chunks.",
            "target_entropy_range": (7.4, 7.95),
            "target_packet_sizes": [517, 1420, 1440, 280],
            "default_transport": "TCP"
        },
        "dns_query": {
            "name": "DNS Query / Tunneling Mimicry",
            "description": "Frames data as valid DNS query datagrams (RFC 1035 format with transaction ID, flags 0x0100, question section), keeps packet sizes small (< 220 bytes), and applies DNS lookup cadence.",
            "target_entropy_range": (3.5, 5.2),
            "target_packet_sizes": [68, 92, 128, 180],
            "default_transport": "UDP"
        },
        "http_api": {
            "name": "HTTP/1.1 REST API Mimicry",
            "description": "Wraps arbitrary payload into HTTP POST/GET requests and 200 OK responses with standard HTTP headers (Host, User-Agent, Content-Type: application/json), exhibiting high ASCII ratio.",
            "target_entropy_range": (4.2, 5.8),
            "target_packet_sizes": [320, 580, 1024],
            "default_transport": "TCP"
        }
    }

    def __init__(self):
        pass

    def transform_flow(
        self,
        flow: FlowRecord,
        target_protocol: str = "tls_https",
        apply_padding: bool = True,
        apply_timing_jitter: bool = True,
        apply_entropy_shaping: bool = True,
        jitter_intensity_ms: float = 25.0
    ) -> FlowRecord:
        """
        Transforms an input flow into the chosen target protocol representation.
        """
        if target_protocol not in self.TARGET_PROTOCOLS:
            target_protocol = "tls_https"

        orig_packets = flow.packets
        transformed_packets: List[PacketRecord] = []
        new_flow_id = f"mimic_{target_protocol}_{flow.flow_id}"

        if not orig_packets:
            return FlowRecord(
                flow_id=new_flow_id,
                traffic_type=f"mimicked_{target_protocol}",
                transport_protocol=self.TARGET_PROTOCOLS[target_protocol]["default_transport"],
                packets=[]
            )

        if target_protocol == "tls_https":
            transformed_packets = self._transform_to_tls(
                orig_packets, apply_padding, apply_entropy_shaping
            )
        elif target_protocol == "dns_query":
            transformed_packets = self._transform_to_dns(
                orig_packets, apply_padding
            )
        elif target_protocol == "http_api":
            transformed_packets = self._transform_to_http(
                orig_packets, apply_padding
            )

        # Apply timing jitter & packet scheduling
        if apply_timing_jitter and len(transformed_packets) > 1:
            transformed_packets = self._apply_timing_shaping(
                transformed_packets, jitter_intensity_ms, target_protocol
            )

        target_transport = self.TARGET_PROTOCOLS[target_protocol]["default_transport"]

        return FlowRecord(
            flow_id=new_flow_id,
            traffic_type=f"mimicked_{target_protocol}",
            transport_protocol=target_transport,
            packets=transformed_packets,
            start_time=transformed_packets[0].timestamp if transformed_packets else flow.start_time,
            end_time=transformed_packets[-1].timestamp if transformed_packets else flow.end_time
        )

    def _transform_to_tls(
        self,
        packets: List[PacketRecord],
        apply_padding: bool,
        apply_entropy_shaping: bool
    ) -> List[PacketRecord]:
        new_packets = []
        base_t = packets[0].timestamp

        # Inject synthetic TLS 1.3 ClientHello as first packet if not already present
        client_hello = self._create_tls_client_hello()
        new_packets.append(PacketRecord(
            timestamp=base_t,
            direction="C->S",
            protocol="TCP",
            size=len(client_hello),
            payload=client_hello
        ))

        # Synthetic ServerHello + ChangeCipherSpec + Finished handshake
        server_hello = self._create_tls_server_hello()
        base_t += 0.025
        new_packets.append(PacketRecord(
            timestamp=base_t,
            direction="S->C",
            protocol="TCP",
            size=len(server_hello),
            payload=server_hello
        ))

        # Wrap subsequent payload packets into TLS 1.3 Application Data Records (0x17)
        for p in packets:
            base_t += random.uniform(0.02, 0.08)
            payload = p.payload

            # Entropy shaping: if raw data has low entropy, add pseudo-random encrypted padding
            if apply_entropy_shaping:
                # Append high-entropy random bytes and inner plaintext tag 0x16 (TLS 1.3 inner type)
                rand_pad = os.urandom(random.randint(16, 48))
                payload = payload + b"\x16" + rand_pad

            # Padding to standard TLS block / chunk sizes
            if apply_padding:
                target_block = 128
                remainder = len(payload) % target_block
                if remainder != 0:
                    payload = payload + os.urandom(target_block - remainder)

            # Construct TLS Record Header:
            # Byte 0: 0x17 (Application Data)
            # Bytes 1-2: 0x03, 0x03 (TLS 1.2 legacy version in record header)
            # Bytes 3-4: Length (2 bytes Big Endian)
            rec_len = len(payload)
            if rec_len > 16384:
                payload = payload[:16384]
                rec_len = 16384
            tls_header = struct.pack("!BHH", 0x17, 0x0303, rec_len)
            framed_packet = tls_header + payload

            new_packets.append(PacketRecord(
                timestamp=base_t,
                direction=p.direction,
                protocol="TCP",
                size=len(framed_packet),
                payload=framed_packet
            ))

        return new_packets

    def _transform_to_dns(
        self,
        packets: List[PacketRecord],
        apply_padding: bool
    ) -> List[PacketRecord]:
        new_packets = []
        base_t = packets[0].timestamp

        for i, p in enumerate(packets):
            base_t += random.uniform(0.04, 0.12)
            # Encode arbitrary payload into DNS labels (e.g. hex encoded)
            hex_chunk = p.payload.hex()[:40]
            if not hex_chunk:
                hex_chunk = "01020304"

            # DNS Query structure:
            # Transaction ID: 2 bytes
            # Flags: 0x0100 (Standard Query, Recursion Desired)
            # Questions: 1, Answer RRs: 0, Authority RRs: 0, Additional RRs: 0
            tx_id = random.randint(1, 65535)
            dns_hdr = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)

            # Query Question: label format: \x08subchunk\x07example\x03com\x00
            lbl_len = min(len(hex_chunk), 32)
            lbl = hex_chunk[:lbl_len].encode()
            qname = bytes([len(lbl)]) + lbl + b"\x07example\x03com\x00"
            qtype_qclass = struct.pack("!HH", 0x0001, 0x0001)  # Type A, Class IN

            dns_payload = dns_hdr + qname + qtype_qclass

            if apply_padding and len(dns_payload) < 80:
                # Add OPT RR pseudo-padding
                dns_payload += b"\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00"

            new_packets.append(PacketRecord(
                timestamp=base_t,
                direction="C->S",
                protocol="UDP",
                size=len(dns_payload),
                payload=dns_payload
            ))

            # DNS Server Response
            base_t += random.uniform(0.015, 0.035)
            resp_flags = 0x8180  # Standard query response, No error
            resp_hdr = struct.pack("!HHHHHH", tx_id, resp_flags, 1, 1, 0, 0)
            answer = qname + struct.pack("!HHIH4s", 0x0001, 0x0001, 300, 4, bytes([93, 184, 216, 34]))
            resp_payload = resp_hdr + qname + qtype_qclass + answer

            new_packets.append(PacketRecord(
                timestamp=base_t,
                direction="S->C",
                protocol="UDP",
                size=len(resp_payload),
                payload=resp_payload
            ))

        return new_packets

    def _transform_to_http(
        self,
        packets: List[PacketRecord],
        apply_padding: bool
    ) -> List[PacketRecord]:
        new_packets = []
        base_t = packets[0].timestamp

        for i, p in enumerate(packets):
            base_t += random.uniform(0.05, 0.15)
            hex_payload = p.payload.hex()
            json_body = f'{{"session_id":"sess_{i}","stream_data":"{hex_payload}","ts":{int(time.time())}}}'
            body_bytes = json_body.encode("utf-8")

            # HTTP POST Request framing
            http_req = (
                f"POST /api/v2/telemetry/event HTTP/1.1\r\n"
                f"Host: telemetry-service.internal.net\r\n"
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body_bytes)}\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
            ).encode("utf-8") + body_bytes

            new_packets.append(PacketRecord(
                timestamp=base_t,
                direction="C->S",
                protocol="TCP",
                size=len(http_req),
                payload=http_req
            ))

            # HTTP 200 OK Response
            base_t += random.uniform(0.02, 0.06)
            resp_body = b'{"status":"success","code":200,"received":true}'
            http_resp = (
                f"HTTP/1.1 200 OK\r\n"
                f"Server: nginx/1.24.0\r\n"
                f"Date: Mon, 12 Oct 2026 05:40:00 GMT\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(resp_body)}\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
            ).encode("utf-8") + resp_body

            new_packets.append(PacketRecord(
                timestamp=base_t,
                direction="S->C",
                protocol="TCP",
                size=len(http_resp),
                payload=http_resp
            ))

        return new_packets

    def _apply_timing_shaping(
        self,
        packets: List[PacketRecord],
        jitter_intensity_ms: float,
        target_protocol: str
    ) -> List[PacketRecord]:
        """Injects timing adjustments and inter-arrival delays."""
        if not packets:
            return packets
        cur_t = packets[0].timestamp
        shaped = []
        for i, p in enumerate(packets):
            if i == 0:
                shaped.append(p)
                continue
            # Target protocol cadence
            if target_protocol == "tls_https":
                base_delay = 0.035 if i < 3 else 0.08
            elif target_protocol == "dns_query":
                base_delay = 0.025 if p.direction == "S->C" else 0.12
            else:
                base_delay = 0.06

            jitter = (random.uniform(-jitter_intensity_ms, jitter_intensity_ms) / 1000.0)
            delta = max(0.005, base_delay + jitter)
            cur_t += delta

            shaped.append(PacketRecord(
                timestamp=cur_t,
                direction=p.direction,
                protocol=p.protocol,
                size=p.size,
                payload=p.payload
            ))
        return shaped

    def _create_tls_client_hello(self) -> bytes:
        """Constructs a compliant TLS 1.3 ClientHello record structure."""
        # TLS Record Header: 0x16 (Handshake), 0x0301 (TLS 1.0 legacy version), length
        # Handshake Type: 0x01 (ClientHello)
        client_random = os.urandom(32)
        session_id = os.urandom(32)
        # Cipher suites: TLS_AES_128_GCM_SHA256 (0x1301), TLS_AES_256_GCM_SHA384 (0x1302)
        ciphers = b"\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f"
        # Extensions: SNI (cloudflare-dns.com), supported_versions (TLS 1.3)
        sni = b"\x00\x00\x00\x17\x00\x15\x00\x00\x12cloudflare-dns.com"
        sup_vers = b"\x00\x2b\x00\x03\x02\x03\x04"
        extensions = sni + sup_vers

        body = (
            b"\x03\x03" +  # Client version 0x0303
            client_random +
            bytes([len(session_id)]) + session_id +
            struct.pack("!H", len(ciphers)) + ciphers +
            b"\x01\x00" +  # Compression methods (null)
            struct.pack("!H", len(extensions)) + extensions
        )
        hs_msg = b"\x01" + struct.pack("!I", len(body))[1:] + body
        rec_hdr = struct.pack("!BHH", 0x16, 0x0301, len(hs_msg))
        return rec_hdr + hs_msg

    def _create_tls_server_hello(self) -> bytes:
        """Constructs a compliant TLS 1.3 ServerHello record structure."""
        server_random = os.urandom(32)
        session_id = os.urandom(32)
        body = (
            b"\x03\x03" +
            server_random +
            bytes([len(session_id)]) + session_id +
            b"\x13\x01" +  # Selected TLS_AES_128_GCM_SHA256
            b"\x00" +      # Compression method null
            b"\x00\x06\x00\x2b\x00\x02\x03\x04" # Supported versions extension TLS 1.3
        )
        hs_msg = b"\x02" + struct.pack("!I", len(body))[1:] + body
        rec_hdr = struct.pack("!BHH", 0x16, 0x0303, len(hs_msg))
        return rec_hdr + hs_msg
