import base64
import hashlib
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def node_id_from_pubkey(pubkey_raw: bytes) -> str:
    return hashlib.sha256(pubkey_raw).hexdigest()


@dataclass
class Identity:
    private_key: ed25519.Ed25519PrivateKey
    public_key_raw: bytes
    node_id: str

    @property
    def public_key_b64(self) -> str:
        return b64e(self.public_key_raw)

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data)


def load_or_create_identity(base_dir: str, profile: str) -> Identity:
    profile_dir = Path(base_dir) / profile
    profile_dir.mkdir(parents=True, exist_ok=True)
    key_path = profile_dir / "ed25519.key"

    if key_path.exists():
        private_bytes = key_path.read_bytes()
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
    else:
        private_key = ed25519.Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path.write_bytes(private_bytes)

    public_key = private_key.public_key()
    pub_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    node_id = node_id_from_pubkey(pub_raw)
    return Identity(private_key=private_key, public_key_raw=pub_raw, node_id=node_id)


def verify_signature(pubkey_raw: bytes, signature: bytes, data: bytes) -> bool:
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pubkey_raw).verify(signature, data)
        return True
    except Exception:
        return False
