import hashlib
import json
from pathlib import Path


class TrustStore:
    def __init__(self, base_dir: str, profile: str) -> None:
        self.path = Path(base_dir) / profile / "trust.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._trusted: set[str] = set()
        self._known_pub_fp: dict[str, str] = {}
        self._load()

    @staticmethod
    def _fingerprint_pub_b64(pub_b64: str) -> str:
        normalized = pub_b64.strip().encode("utf-8")
        return hashlib.sha256(normalized).hexdigest()

    def _load(self) -> None:
        if not self.path.exists():
            self._trusted = set()
            self._known_pub_fp = {}
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            nodes = raw.get("trusted", []) if isinstance(raw, dict) else []
            known = raw.get("known_pub_fp", {}) if isinstance(raw, dict) else {}
            self._trusted = {str(n) for n in nodes if isinstance(n, str)}
            self._known_pub_fp = {str(k): str(v) for k, v in known.items()} if isinstance(known, dict) else {}
        except Exception:
            self._trusted = set()
            self._known_pub_fp = {}

    def _save(self) -> None:
        payload = {
            "trusted": sorted(self._trusted),
            "known_pub_fp": dict(sorted(self._known_pub_fp.items())),
        }
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def trust(self, node_id: str) -> None:
        self._trusted.add(node_id)
        self._save()

    def untrust(self, node_id: str) -> None:
        if node_id in self._trusted:
            self._trusted.remove(node_id)
            self._save()

    def is_trusted(self, node_id: str) -> bool:
        return node_id in self._trusted

    def list_trusted(self) -> list[str]:
        return sorted(self._trusted)

    def observe_peer_key(self, node_id: str, ed25519_pub_b64: str, auto_trust: bool = True) -> str:
        node_id = str(node_id).strip()
        pub = str(ed25519_pub_b64).strip()
        if not node_id or not pub:
            return "ignore"

        fp = self._fingerprint_pub_b64(pub)
        existing = self._known_pub_fp.get(node_id)
        if existing is None:
            self._known_pub_fp[node_id] = fp
            if auto_trust:
                self._trusted.add(node_id)
            self._save()
            return "new_trusted" if auto_trust else "new_known"

        if existing != fp:
            if node_id in self._trusted:
                self._trusted.remove(node_id)
            self._save()
            return "mismatch"

        return "known"

