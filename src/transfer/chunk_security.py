import hashlib
import json
from typing import Any, Optional

from crypto.identity import Identity, b64d, b64e, node_id_from_pubkey, verify_signature


def _canonical_chunk_bytes(payload: dict[str, Any]) -> bytes:
    core = {
        "file_id": payload.get("file_id"),
        "index": payload.get("index"),
        "hash": payload.get("hash"),
        "size": payload.get("size"),
    }
    return json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")


def chunk_digest(payload: dict[str, Any]) -> bytes:
    return hashlib.sha256(_canonical_chunk_bytes(payload)).digest()


def sign_chunk_payload(payload: dict[str, Any], identity: Identity) -> dict[str, Any]:
    signed = dict(payload)
    signed["sender_id"] = identity.public_key_raw.hex()
    signed["signature"] = b64e(identity.sign(chunk_digest(signed)))
    return signed


def verify_chunk_signature(payload: dict[str, Any], expected_node_id: Optional[str] = None) -> bool:
    sender_pub_hex = str(payload.get("sender_id", ""))
    signature_b64 = str(payload.get("signature", ""))
    if not sender_pub_hex or not signature_b64:
        return False

    try:
        sender_pub_raw = bytes.fromhex(sender_pub_hex)
        signature = b64d(signature_b64)
    except Exception:
        return False

    sender_node_id = node_id_from_pubkey(sender_pub_raw)
    if expected_node_id and sender_node_id != expected_node_id:
        return False

    return verify_signature(sender_pub_raw, signature, chunk_digest(payload))
