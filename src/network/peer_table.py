import json
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class Peer:
    node_id: str
    ip: str
    tcp_port: int
    last_seen: float
    ed25519_pub: str = ""
    shared_files: list[str] = field(default_factory=list)
    reputation: float = 1.0
    success_chunks: int = 0
    failed_chunks: int = 0


class PeerTable:
    def __init__(self, ttl_seconds: int = 90, persist_path: Optional[str] = None) -> None:
        self._ttl_seconds = ttl_seconds
        self._peers: Dict[str, Peer] = {}
        self._lock = threading.Lock()
        self._persist_path = Path(persist_path) if persist_path else None
        if self._persist_path:
            self._persist_path.parent.mkdir(parents=True, exist_ok=True)
            self._load()

    def _load(self) -> None:
        if not self._persist_path or not self._persist_path.exists():
            return
        try:
            raw = json.loads(self._persist_path.read_text(encoding="utf-8"))
            if not isinstance(raw, list):
                return
            now = time.time()
            for item in raw:
                if not isinstance(item, dict):
                    continue
                node_id = str(item.get("node_id", ""))
                ip = str(item.get("ip", ""))
                tcp_port = int(item.get("tcp_port", 0))
                last_seen = float(item.get("last_seen", now))
                ed25519_pub = str(item.get("ed25519_pub", ""))
                shared_raw = item.get("shared_files", [])
                shared_files = [str(x) for x in shared_raw] if isinstance(shared_raw, list) else []
                reputation = float(item.get("reputation", 1.0))
                success_chunks = int(item.get("success_chunks", 0))
                failed_chunks = int(item.get("failed_chunks", 0))
                if node_id and ip and tcp_port > 0:
                    self._peers[node_id] = Peer(
                        node_id=node_id,
                        ip=ip,
                        tcp_port=tcp_port,
                        last_seen=last_seen,
                        ed25519_pub=ed25519_pub,
                        shared_files=shared_files,
                        reputation=max(0.0, min(1.0, reputation)),
                        success_chunks=max(0, success_chunks),
                        failed_chunks=max(0, failed_chunks),
                    )
        except Exception:
            return

    def _save_locked(self) -> None:
        if not self._persist_path:
            return
        payload = [asdict(peer) for peer in self._peers.values()]
        payload.sort(key=lambda p: p["node_id"])
        self._persist_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def upsert(
        self,
        node_id: str,
        ip: str,
        tcp_port: int,
        ed25519_pub: str = "",
        seen_at: Optional[float] = None,
    ) -> None:
        ts = seen_at if seen_at is not None else time.time()
        with self._lock:
            existing = self._peers.get(node_id)
            pub = ed25519_pub or (existing.ed25519_pub if existing else "")
            self._peers[node_id] = Peer(
                node_id=node_id,
                ip=ip,
                tcp_port=tcp_port,
                last_seen=ts,
                ed25519_pub=pub,
                shared_files=list(existing.shared_files) if existing else [],
                reputation=float(existing.reputation) if existing else 1.0,
                success_chunks=int(existing.success_chunks) if existing else 0,
                failed_chunks=int(existing.failed_chunks) if existing else 0,
            )
            self._save_locked()

    def note_shared_file(self, node_id: str, file_id: str) -> None:
        file_id = str(file_id).strip()
        if not file_id:
            return
        with self._lock:
            peer = self._peers.get(node_id)
            if peer is None:
                return
            if file_id in peer.shared_files:
                return
            peer.shared_files.append(file_id)
            if len(peer.shared_files) > 200:
                peer.shared_files = peer.shared_files[-200:]
            self._save_locked()

    def record_chunk_result(self, node_id: str, ok: bool) -> None:
        with self._lock:
            peer = self._peers.get(node_id)
            if peer is None:
                return
            if ok:
                peer.success_chunks += 1
            else:
                peer.failed_chunks += 1
            total = peer.success_chunks + peer.failed_chunks
            peer.reputation = (peer.success_chunks / total) if total > 0 else 1.0
            self._save_locked()

    def remove_stale(self) -> List[str]:
        now = time.time()
        removed: List[str] = []
        with self._lock:
            stale = [nid for nid, peer in self._peers.items() if now - peer.last_seen > self._ttl_seconds]
            for nid in stale:
                del self._peers[nid]
                removed.append(nid)
            if removed:
                self._save_locked()
        return removed

    def get(self, node_id: str) -> Optional[Peer]:
        with self._lock:
            return self._peers.get(node_id)

    def resolve(self, selector: str) -> Optional[Peer]:
        with self._lock:
            if selector in self._peers:
                return self._peers[selector]
            matches = [p for nid, p in self._peers.items() if nid.startswith(selector)]
            if len(matches) == 1:
                return matches[0]
        return None

    def to_list(self) -> List[dict]:
        with self._lock:
            peers = [asdict(peer) for peer in self._peers.values()]
        peers.sort(key=lambda p: p["node_id"])
        return peers

    def to_json(self) -> str:
        return json.dumps(self.to_list(), indent=2)

