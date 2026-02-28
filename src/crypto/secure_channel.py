import json
import os
import time
from dataclasses import dataclass
from typing import Any, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from network.packet_v1 import (
    CONTROL_HMAC_KEY,
    PT_HS1,
    PT_HS2,
    PT_HS3,
    PT_MSG_SECURE,
    decode_tlvs,
    encode_tlvs,
    read_packet,
    write_packet,
)

from .identity import Identity, b64e, node_id_matches_pubkey, verify_signature

TLV_HS_ED25519_PUB = 0x01
TLV_HS_EPH_PUB = 0x02
TLV_HS_TIMESTAMP = 0x03
TLV_HS_SIGNATURE = 0x04

TLV_SEQ = 0x01
TLV_TS = 0x02
TLV_NONCE = 0x03
TLV_CIPHERTEXT = 0x04


def canonical_bytes(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def derive_session_key(shared_secret: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"archipel-v1")
    return hkdf.derive(shared_secret)


@dataclass
class Session:
    remote_node_id: str
    key: bytes
    tx_seq: int = 0
    rx_max_seq: int = -1


def _tlv_first(payload: bytes, t: int) -> bytes:
    for kind, value in decode_tlvs(payload):
        if kind == t:
            return value
    raise ValueError(f"TLV manquant: {t}")


def _encode_secure_record(session: Session, payload: dict[str, Any]) -> bytes:
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    nonce = os.urandom(12)

    seq = session.tx_seq
    ts = int(time.time() * 1000)
    seq_b = seq.to_bytes(8, "big")
    ts_b = ts.to_bytes(8, "big")

    aesgcm = AESGCM(session.key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, seq_b)
    session.tx_seq += 1

    return encode_tlvs(
        [
            (TLV_SEQ, seq_b),
            (TLV_TS, ts_b),
            (TLV_NONCE, nonce),
            (TLV_CIPHERTEXT, ciphertext),
        ]
    )


def _decode_secure_record(session: Session, record: bytes, replay_window: int = 1024) -> dict[str, Any]:
    seq_b = _tlv_first(record, TLV_SEQ)
    nonce = _tlv_first(record, TLV_NONCE)
    ciphertext = _tlv_first(record, TLV_CIPHERTEXT)

    if len(seq_b) != 8:
        raise ValueError("seq invalide")
    if len(nonce) != 12:
        raise ValueError("nonce invalide")

    seq = int.from_bytes(seq_b, "big")
    if seq <= session.rx_max_seq - replay_window:
        raise ValueError("replay détecté")

    aesgcm = AESGCM(session.key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, seq_b)

    if seq > session.rx_max_seq:
        session.rx_max_seq = seq

    return json.loads(plaintext.decode("utf-8"))


def send_secure_payload(stream, session: Session, local_node_id: str, payload: dict[str, Any]) -> None:
    record = _encode_secure_record(session, payload)
    write_packet(stream, PT_MSG_SECURE, local_node_id, record, session.key)


def recv_secure_payload(stream, session: Session) -> Optional[dict[str, Any]]:
    pkt = read_packet(stream, session.key)
    if pkt is None:
        return None
    if pkt["type"] != PT_MSG_SECURE:
        raise ValueError("type paquet sécurisé invalide")
    if pkt["node_id"] != session.remote_node_id:
        raise ValueError("node_id paquet sécurisé inattendu")
    return _decode_secure_record(session, pkt["payload"])


def initiator_handshake(conn, identity: Identity) -> tuple[Session, Any]:
    stream = conn.makefile("rwb")

    e_priv = x25519.X25519PrivateKey.generate()
    e_pub = e_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ts1 = int(time.time() * 1000)

    hs1_payload = encode_tlvs(
        [
            (TLV_HS_ED25519_PUB, identity.public_key_raw),
            (TLV_HS_EPH_PUB, e_pub),
            (TLV_HS_TIMESTAMP, ts1.to_bytes(8, "big")),
        ]
    )
    write_packet(stream, PT_HS1, identity.node_id, hs1_payload, CONTROL_HMAC_KEY)

    hs2 = read_packet(stream, CONTROL_HMAC_KEY)
    if hs2 is None or hs2["type"] != PT_HS2:
        raise ValueError("HS2 invalide")

    remote_node_id = str(hs2["node_id"])
    remote_pub = _tlv_first(hs2["payload"], TLV_HS_ED25519_PUB)
    remote_e_pub_raw = _tlv_first(hs2["payload"], TLV_HS_EPH_PUB)
    ts2_b = _tlv_first(hs2["payload"], TLV_HS_TIMESTAMP)
    sig2 = _tlv_first(hs2["payload"], TLV_HS_SIGNATURE)

    if not node_id_matches_pubkey(remote_node_id, remote_pub):
        raise ValueError("node_id distant invalide")

    hs1_view = {
        "type": "HS1",
        "node_id": identity.node_id,
        "ed25519_pub": b64e(identity.public_key_raw),
        "e_pub": b64e(e_pub),
        "ts": ts1,
    }
    hs2_view = {
        "type": "HS2",
        "node_id": remote_node_id,
        "ed25519_pub": b64e(remote_pub),
        "e_pub": b64e(remote_e_pub_raw),
        "ts": int.from_bytes(ts2_b, "big"),
    }

    transcript_hash = hashes.Hash(hashes.SHA256())
    transcript_hash.update(canonical_bytes(hs1_view))
    transcript_hash.update(canonical_bytes(hs2_view))
    th = transcript_hash.finalize()

    if not verify_signature(remote_pub, sig2, th):
        raise ValueError("signature HS2 invalide")

    remote_e_pub = x25519.X25519PublicKey.from_public_bytes(remote_e_pub_raw)
    key = derive_session_key(e_priv.exchange(remote_e_pub))

    ts3 = int(time.time() * 1000)
    sig3 = identity.sign(th)
    hs3_payload = encode_tlvs(
        [
            (TLV_HS_SIGNATURE, sig3),
            (TLV_HS_TIMESTAMP, ts3.to_bytes(8, "big")),
        ]
    )
    write_packet(stream, PT_HS3, identity.node_id, hs3_payload, CONTROL_HMAC_KEY)

    return Session(remote_node_id=remote_node_id, key=key), stream


def responder_handshake(stream, identity: Identity, hs1_packet: dict[str, Any]) -> Session:
    if hs1_packet["type"] != PT_HS1:
        raise ValueError("HS1 invalide")

    remote_node_id = str(hs1_packet["node_id"])
    remote_pub = _tlv_first(hs1_packet["payload"], TLV_HS_ED25519_PUB)
    remote_e_pub_raw = _tlv_first(hs1_packet["payload"], TLV_HS_EPH_PUB)
    ts1_b = _tlv_first(hs1_packet["payload"], TLV_HS_TIMESTAMP)

    if not node_id_matches_pubkey(remote_node_id, remote_pub):
        raise ValueError("node_id HS1 invalide")

    e_priv = x25519.X25519PrivateKey.generate()
    e_pub = e_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ts2 = int(time.time() * 1000)

    hs1_view = {
        "type": "HS1",
        "node_id": remote_node_id,
        "ed25519_pub": b64e(remote_pub),
        "e_pub": b64e(remote_e_pub_raw),
        "ts": int.from_bytes(ts1_b, "big"),
    }
    hs2_view = {
        "type": "HS2",
        "node_id": identity.node_id,
        "ed25519_pub": b64e(identity.public_key_raw),
        "e_pub": b64e(e_pub),
        "ts": ts2,
    }

    transcript_hash = hashes.Hash(hashes.SHA256())
    transcript_hash.update(canonical_bytes(hs1_view))
    transcript_hash.update(canonical_bytes(hs2_view))
    th = transcript_hash.finalize()

    sig2 = identity.sign(th)
    hs2_payload = encode_tlvs(
        [
            (TLV_HS_ED25519_PUB, identity.public_key_raw),
            (TLV_HS_EPH_PUB, e_pub),
            (TLV_HS_TIMESTAMP, ts2.to_bytes(8, "big")),
            (TLV_HS_SIGNATURE, sig2),
        ]
    )
    write_packet(stream, PT_HS2, identity.node_id, hs2_payload, CONTROL_HMAC_KEY)

    hs3 = read_packet(stream, CONTROL_HMAC_KEY)
    if hs3 is None or hs3["type"] != PT_HS3:
        raise ValueError("HS3 invalide")
    if str(hs3["node_id"]) != remote_node_id:
        raise ValueError("node_id HS3 invalide")

    sig3 = _tlv_first(hs3["payload"], TLV_HS_SIGNATURE)
    if not verify_signature(remote_pub, sig3, th):
        raise ValueError("signature HS3 invalide")

    remote_e_pub = x25519.X25519PublicKey.from_public_bytes(remote_e_pub_raw)
    key = derive_session_key(e_priv.exchange(remote_e_pub))

    return Session(remote_node_id=remote_node_id, key=key)
