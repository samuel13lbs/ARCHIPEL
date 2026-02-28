import hashlib
import json
from typing import Any

from crypto.identity import Identity, b64d, b64e, node_id_from_pubkey, verify_signature


def _canonical_manifest_bytes(manifest: dict[str, Any]) -> bytes:
    core = {k: v for k, v in manifest.items() if k != "signature"}
    return json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")


def manifest_digest(manifest: dict[str, Any]) -> bytes:
    return hashlib.sha256(_canonical_manifest_bytes(manifest)).digest()


def sign_manifest(manifest: dict[str, Any], identity: Identity) -> dict[str, Any]:
    signed = dict(manifest)
    digest = manifest_digest(signed)
    signed["signature"] = b64e(identity.sign(digest))
    return signed


def verify_manifest_signature(manifest: dict[str, Any]) -> bool:
    sender_pub_hex = str(manifest.get("sender_id", ""))
    signature_b64 = str(manifest.get("signature", ""))
    if not sender_pub_hex or not signature_b64:
        return False

    try:
        sender_pub_raw = bytes.fromhex(sender_pub_hex)
        signature = b64d(signature_b64)
    except Exception:
        return False

    digest = manifest_digest(manifest)
    return verify_signature(sender_pub_raw, signature, digest)


def manifest_sender_node_id(manifest: dict[str, Any]) -> str:
    sender_pub_hex = str(manifest.get("sender_id", ""))
    sender_pub_raw = bytes.fromhex(sender_pub_hex)
    return node_id_from_pubkey(sender_pub_raw)
