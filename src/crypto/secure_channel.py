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

from .identity import Identity, b64d, b64e, node_id_from_pubkey, verify_signature


def canonical_bytes(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def read_json_line(reader) -> Optional[dict[str, Any]]:
    line = reader.readline()
    if not line:
        return None
    return json.loads(line.decode("utf-8"))


def write_json_line(writer, payload: dict[str, Any]) -> None:
    writer.write((json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8"))
    writer.flush()


def derive_session_key(shared_secret: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"archipel-v1")
    return hkdf.derive(shared_secret)


@dataclass
class Session:
    remote_node_id: str
    key: bytes
    tx_seq: int = 0
    rx_max_seq: int = -1


def _encrypt_bytes(session: Session, plaintext: bytes) -> dict[str, Any]:
    nonce = os.urandom(12)
    aesgcm = AESGCM(session.key)
    aad = f"{session.tx_seq}".encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    pkt = {
        "type": "MSG_ENC",
        "seq": session.tx_seq,
        "ts": int(time.time() * 1000),
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
    }
    session.tx_seq += 1
    return pkt


def _decrypt_bytes(session: Session, msg: dict[str, Any], replay_window: int = 1024) -> bytes:
    seq = int(msg.get("seq", -1))
    if seq < 0:
        raise ValueError("seq manquant")
    if seq <= session.rx_max_seq - replay_window:
        raise ValueError("replay détecté")

    nonce = b64d(str(msg["nonce"]))
    ciphertext = b64d(str(msg["ciphertext"]))
    aad = f"{seq}".encode("utf-8")

    aesgcm = AESGCM(session.key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)

    if seq > session.rx_max_seq:
        session.rx_max_seq = seq
    return plaintext


def encrypt_payload(session: Session, payload: dict[str, Any]) -> dict[str, Any]:
    return _encrypt_bytes(session, json.dumps(payload, separators=(",", ":")).encode("utf-8"))


def decrypt_payload(session: Session, msg: dict[str, Any]) -> dict[str, Any]:
    raw = _decrypt_bytes(session, msg)
    return json.loads(raw.decode("utf-8"))


def encrypt_message(session: Session, plaintext: str) -> dict[str, Any]:
    return encrypt_payload(session, {"kind": "CHAT", "text": plaintext})


def decrypt_message(session: Session, msg: dict[str, Any], replay_window: int = 1024) -> str:
    payload = decrypt_payload(session, msg)
    if payload.get("kind") != "CHAT":
        raise ValueError("payload non-CHAT")
    return str(payload.get("text", ""))


def initiator_handshake(conn, identity: Identity) -> tuple[Session, Any]:
    reader = conn.makefile("rwb")
    e_priv = x25519.X25519PrivateKey.generate()
    e_pub = e_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    hs1 = {
        "type": "HS1",
        "node_id": identity.node_id,
        "ed25519_pub": identity.public_key_b64,
        "e_pub": b64e(e_pub),
        "ts": int(time.time() * 1000),
    }
    write_json_line(reader, hs1)

    hs2 = read_json_line(reader)
    if not hs2 or hs2.get("type") != "HS2":
        raise ValueError("HS2 invalide")

    remote_node_id = str(hs2.get("node_id", ""))
    remote_pub = b64d(str(hs2.get("ed25519_pub", "")))
    if node_id_from_pubkey(remote_pub) != remote_node_id:
        raise ValueError("node_id distant invalide")

    hs2_basic = {
        "type": "HS2",
        "node_id": remote_node_id,
        "ed25519_pub": hs2["ed25519_pub"],
        "e_pub": hs2["e_pub"],
        "ts": hs2["ts"],
    }
    transcript_hash = hashes.Hash(hashes.SHA256())
    transcript_hash.update(canonical_bytes(hs1))
    transcript_hash.update(canonical_bytes(hs2_basic))
    th = transcript_hash.finalize()

    if not verify_signature(remote_pub, b64d(str(hs2.get("sig", ""))), th):
        raise ValueError("signature HS2 invalide")

    remote_e_pub = x25519.X25519PublicKey.from_public_bytes(b64d(str(hs2["e_pub"])))
    key = derive_session_key(e_priv.exchange(remote_e_pub))

    hs3 = {
        "type": "HS3",
        "node_id": identity.node_id,
        "sig": b64e(identity.sign(th)),
        "ts": int(time.time() * 1000),
    }
    write_json_line(reader, hs3)
    return Session(remote_node_id=remote_node_id, key=key), reader


def responder_handshake(reader, identity: Identity, hs1: dict[str, Any]) -> Session:
    if hs1.get("type") != "HS1":
        raise ValueError("HS1 invalide")

    remote_node_id = str(hs1.get("node_id", ""))
    remote_pub = b64d(str(hs1.get("ed25519_pub", "")))
    if node_id_from_pubkey(remote_pub) != remote_node_id:
        raise ValueError("node_id HS1 invalide")

    e_priv = x25519.X25519PrivateKey.generate()
    e_pub = e_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    hs2_basic = {
        "type": "HS2",
        "node_id": identity.node_id,
        "ed25519_pub": identity.public_key_b64,
        "e_pub": b64e(e_pub),
        "ts": int(time.time() * 1000),
    }

    transcript_hash = hashes.Hash(hashes.SHA256())
    transcript_hash.update(canonical_bytes(hs1))
    transcript_hash.update(canonical_bytes(hs2_basic))
    th = transcript_hash.finalize()

    hs2 = dict(hs2_basic)
    hs2["sig"] = b64e(identity.sign(th))
    write_json_line(reader, hs2)

    hs3 = read_json_line(reader)
    if not hs3 or hs3.get("type") != "HS3":
        raise ValueError("HS3 invalide")
    if str(hs3.get("node_id", "")) != remote_node_id:
        raise ValueError("node_id HS3 invalide")
    if not verify_signature(remote_pub, b64d(str(hs3.get("sig", ""))), th):
        raise ValueError("signature HS3 invalide")

    remote_e_pub = x25519.X25519PublicKey.from_public_bytes(b64d(str(hs1["e_pub"])))
    key = derive_session_key(e_priv.exchange(remote_e_pub))

    return Session(remote_node_id=remote_node_id, key=key)
