import hashlib
import hmac
import os
import struct
from typing import Optional

MAGIC = b"ARCP"
HEADER_FMT = ">4sB32sI"
HEADER_LEN = struct.calcsize(HEADER_FMT)  # 41 bytes
HMAC_LEN = 32

# Packet types (v1)
PT_HELLO = 0x01
PT_PEER_LIST = 0x02
PT_MSG_SECURE = 0x03
PT_HS1 = 0x10
PT_HS2 = 0x11
PT_HS3 = 0x12


def _control_hmac_key_from_env() -> bytes:
    raw = os.getenv("ARCHIPEL_CONTROL_HMAC_KEY", "").strip()
    if not raw:
        return b"\x00" * 32
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        return b"\x00" * 32
    return key if len(key) == 32 else (b"\x00" * 32)


CONTROL_HMAC_KEY = _control_hmac_key_from_env()


def encode_tlvs(items: list[tuple[int, bytes]]) -> bytes:
    out = bytearray()
    for t, v in items:
        if t < 0 or t > 255:
            raise ValueError("type TLV invalide")
        out.extend(struct.pack(">BI", t, len(v)))
        out.extend(v)
    return bytes(out)


def decode_tlvs(data: bytes) -> list[tuple[int, bytes]]:
    out: list[tuple[int, bytes]] = []
    i = 0
    n = len(data)
    while i < n:
        if i + 5 > n:
            raise ValueError("TLV tronque")
        t, ln = struct.unpack(">BI", data[i : i + 5])
        i += 5
        if i + ln > n:
            raise ValueError("TLV length invalide")
        out.append((t, data[i : i + ln]))
        i += ln
    return out


def _read_exact(stream, size: int) -> Optional[bytes]:
    buf = bytearray()
    while len(buf) < size:
        chunk = stream.read(size - len(buf))
        if chunk is None or len(chunk) == 0:
            if len(buf) == 0:
                return None
            raise EOFError("flux ferme au milieu d'un paquet")
        buf.extend(chunk)
    return bytes(buf)


def pack_packet(packet_type: int, node_id_hex: str, payload: bytes, hmac_key: bytes) -> bytes:
    node_id = bytes.fromhex(node_id_hex)
    if len(node_id) != 32:
        raise ValueError("node_id doit faire 32 bytes")
    if packet_type < 0 or packet_type > 255:
        raise ValueError("packet type invalide")

    header = struct.pack(HEADER_FMT, MAGIC, packet_type, node_id, len(payload))
    sig = hmac.new(hmac_key, header + payload, hashlib.sha256).digest()
    return header + payload + sig


def unpack_packet(data: bytes, hmac_key: bytes) -> dict:
    if len(data) < HEADER_LEN + HMAC_LEN:
        raise ValueError("paquet trop court")

    header = data[:HEADER_LEN]
    magic, packet_type, node_id, payload_len = struct.unpack(HEADER_FMT, header)
    if magic != MAGIC:
        raise ValueError("magic paquet invalide")

    expected_len = HEADER_LEN + payload_len + HMAC_LEN
    if len(data) != expected_len:
        raise ValueError("taille paquet invalide")

    payload = data[HEADER_LEN : HEADER_LEN + payload_len]
    sig = data[-HMAC_LEN:]
    expected = hmac.new(hmac_key, header + payload, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        raise ValueError("HMAC invalide")

    return {
        "type": packet_type,
        "node_id": node_id.hex(),
        "payload": payload,
    }


def write_packet(stream, packet_type: int, node_id_hex: str, payload: bytes, hmac_key: bytes) -> None:
    stream.write(pack_packet(packet_type, node_id_hex, payload, hmac_key))
    stream.flush()


def read_packet(stream, hmac_key: bytes) -> Optional[dict]:
    header = _read_exact(stream, HEADER_LEN)
    if header is None:
        return None
    magic, packet_type, node_id, payload_len = struct.unpack(HEADER_FMT, header)
    if magic != MAGIC:
        raise ValueError("magic paquet invalide")

    payload = _read_exact(stream, payload_len)
    if payload is None:
        raise EOFError("payload manquant")

    sig = _read_exact(stream, HMAC_LEN)
    if sig is None:
        raise EOFError("signature HMAC manquante")

    expected = hmac.new(hmac_key, header + payload, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        raise ValueError("HMAC invalide")

    return {
        "type": packet_type,
        "node_id": node_id.hex(),
        "payload": payload,
    }
