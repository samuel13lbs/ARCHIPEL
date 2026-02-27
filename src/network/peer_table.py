import json
import threading
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional


@dataclass
class Peer:
    node_id: str
    ip: str
    tcp_port: int
    last_seen: float
    ed25519_pub: str = ""


class PeerTable:
    def __init__(self, ttl_seconds: int = 90) -> None:
        self._ttl_seconds = ttl_seconds
        self._peers: Dict[str, Peer] = {}
        self._lock = threading.Lock()

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
            )

    def remove_stale(self) -> List[str]:
        now = time.time()
        removed: List[str] = []
        with self._lock:
            stale = [nid for nid, peer in self._peers.items() if now - peer.last_seen > self._ttl_seconds]
            for nid in stale:
                del self._peers[nid]
                removed.append(nid)
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
