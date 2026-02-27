import json
from pathlib import Path


class TrustStore:
    def __init__(self, base_dir: str, profile: str) -> None:
        self.path = Path(base_dir) / profile / "trust.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._trusted: set[str] = set()
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            self._trusted = set()
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            nodes = raw.get("trusted", []) if isinstance(raw, dict) else []
            self._trusted = {str(n) for n in nodes if isinstance(n, str)}
        except Exception:
            self._trusted = set()

    def _save(self) -> None:
        payload = {"trusted": sorted(self._trusted)}
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
