import concurrent.futures as cf
import base64
import hashlib
import json
import random
import shlex
import threading
import time
from collections import deque
from pathlib import Path
from typing import Callable, Optional

from crypto.identity import b64d, load_or_create_identity, node_id_matches_pubkey
from messaging.gemini_client import GeminiClient
from network.discovery import DiscoveryService
from network.peer_table import Peer
from network.peer_table import PeerTable
from network.tcp_server import TcpServer
from security.trust_store import TrustStore
from transfer.manifest_security import sign_manifest
from transfer.chunk_security import verify_chunk_signature
from transfer.manager import TransferManager, sha256_bytes


class ArchipelRuntime:
    def __init__(
        self,
        port: int,
        hello_interval: int,
        state_dir: str,
        logger: Callable[[str], None],
        ai_enabled: bool = True,
        ai_context_messages: int = 12,
        tofu_auto: bool = True,
        auto_mode: bool = False,
        auto_send_dir: str = "",
        replication_factor: int = 1,
    ) -> None:
        self.port = port
        self.hello_interval = hello_interval
        self.state_dir = state_dir
        self.log = logger
        self.tofu_auto = tofu_auto
        self.auto_mode = auto_mode
        self.replication_factor = max(1, int(replication_factor))
        self._chat_history: deque[dict] = deque(maxlen=2000)
        self._chat_lock = threading.Lock()
        self.ai_context_messages = max(1, ai_context_messages)
        self.ai = GeminiClient.from_env(enabled=ai_enabled, logger=self.log)
        self._bg_stop = threading.Event()
        self._auto_download_done: set[str] = set()
        self._auto_download_next_try: dict[str, float] = {}
        self._auto_send_seen: set[str] = set()

        self.profile = f"node-{port}"
        self._chat_path = Path(state_dir) / self.profile / "chat_history.jsonl"
        self._chat_path.parent.mkdir(parents=True, exist_ok=True)
        self._load_chat_history()
        default_auto_send_dir = Path(state_dir) / self.profile / "auto-send"
        self.auto_send_dir = Path(auto_send_dir).expanduser() if auto_send_dir else default_auto_send_dir
        if self.auto_mode:
            self.auto_send_dir.mkdir(parents=True, exist_ok=True)
        self.identity = load_or_create_identity(state_dir, profile=self.profile)
        self.trust = TrustStore(state_dir, profile=self.profile)
        peer_table_path = Path(state_dir) / self.profile / "peers.json"
        self.table = PeerTable(ttl_seconds=90, persist_path=str(peer_table_path))
        self.transfer = TransferManager(state_dir, profile=self.profile)

        self.tcp = TcpServer(
            identity=self.identity,
            listen_port=port,
            peer_table=self.table,
            transfer=self.transfer,
            logger=self.log,
            is_trusted=self.trust.is_trusted,
            on_chat=self._on_chat_received,
        )
        self.discovery = DiscoveryService(
            node_id=self.identity.node_id,
            ed25519_pub=self.identity.public_key_b64,
            tcp_port=port,
            peer_table=self.table,
            logger=self.log,
            hello_interval_seconds=hello_interval,
        )

    def start(self) -> None:
        self.log(f"[NODE] node_id={self.identity.node_id}")
        self.log(f"[NODE] pubkey_b64={self.identity.public_key_b64}")
        ai_state = self.ai.status()
        self.log(
            f"[AI] enabled={ai_state['enabled']} configured={ai_state['configured']} model={ai_state['model']}"
        )
        self.tcp.start()
        self.discovery.start()
        if self.tofu_auto:
            self.log("[TRUST] TOFU automatique actif")
            threading.Thread(target=self._tofu_trust_loop, daemon=True).start()
        if self.auto_mode:
            self.log(
                f"[AUTO] mode=on auto_send_dir={self.auto_send_dir} replication_factor={self.replication_factor}"
            )
            threading.Thread(target=self._auto_trust_loop, daemon=True).start()
            threading.Thread(target=self._auto_download_loop, daemon=True).start()
            threading.Thread(target=self._auto_send_loop, daemon=True).start()

    def stop(self) -> None:
        self.log("[NODE] Arrêt...")
        self._bg_stop.set()
        self.discovery.stop()
        self.tcp.stop()

    def status_snapshot(self) -> dict:
        peers = self.table.to_list()
        trusted_count = sum(1 for p in peers if self.trust.is_trusted(str(p.get("node_id", ""))))
        return {
            "node_id": self.identity.node_id,
            "tcp_port": self.port,
            "peers": len(peers),
            "trusted": trusted_count,
            "manifests": len(self.transfer.list_manifests()),
        }

    def peers_payload(self) -> list[dict]:
        peers = self.table.to_list()
        for p in peers:
            p["trusted"] = self.trust.is_trusted(str(p.get("node_id", "")))
        return peers

    def ai_status_payload(self) -> dict:
        return self.ai.status()

    def auto_status_payload(self) -> dict:
        return {
            "enabled": self.auto_mode,
            "tofu_auto": self.tofu_auto,
            "replication_factor": self.replication_factor,
            "auto_send_dir": str(self.auto_send_dir),
            "auto_download_done": len(self._auto_download_done),
            "auto_download_pending": len(self._auto_download_next_try),
        }

    def _load_chat_history(self) -> None:
        if not self._chat_path.exists():
            return
        try:
            with self._chat_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    item = json.loads(line)
                    if not isinstance(item, dict):
                        continue
                    role = str(item.get("role", "")).strip()
                    text = str(item.get("text", "")).strip()
                    peer = str(item.get("peer", "")).strip()
                    ts = int(item.get("ts", int(time.time() * 1000)))
                    if not role or not text:
                        continue
                    self._chat_history.append({"ts": ts, "role": role, "peer": peer, "text": text})
        except Exception as exc:
            self.log(f"[CHAT] Historique ignoré: {exc}")

    def _append_chat_entry(self, entry: dict) -> None:
        try:
            with self._chat_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as exc:
            self.log(f"[CHAT] Echec sauvegarde historique: {exc}")

    def chat_history_payload(self, limit: int = 30) -> list[dict]:
        if limit <= 0:
            return []
        with self._chat_lock:
            return list(self._chat_history)[-limit:]

    def _record_chat(self, role: str, text: str, peer_node_id: str = "") -> None:
        text = text.strip()
        if not text:
            return
        entry = {
            "ts": int(time.time() * 1000),
            "role": role,
            "peer": peer_node_id,
            "text": text,
        }
        with self._chat_lock:
            self._chat_history.append(entry)
        self._append_chat_entry(entry)

    def conversations_payload(self, limit: int = 100) -> list[dict]:
        latest_by_peer: dict[str, dict] = {}
        with self._chat_lock:
            entries = list(self._chat_history)

        for item in entries:
            role = str(item.get("role", ""))
            peer = str(item.get("peer", ""))
            if role not in {"me", "peer"} or not peer:
                continue
            prev = latest_by_peer.get(peer)
            if prev is None or int(item.get("ts", 0)) >= int(prev.get("ts", 0)):
                latest_by_peer[peer] = item

        rows: list[dict] = []
        for peer_id, last in latest_by_peer.items():
            peer = self.table.get(peer_id)
            rows.append(
                {
                    "peer_id": peer_id,
                    "peer_short": f"{peer_id[:12]}...",
                    "trusted": self.trust.is_trusted(peer_id),
                    "online": peer is not None,
                    "ip": peer.ip if peer is not None else "",
                    "tcp_port": peer.tcp_port if peer is not None else 0,
                    "last_ts": int(last.get("ts", 0)),
                    "last_role": str(last.get("role", "")),
                    "last_text": str(last.get("text", "")),
                }
            )

        rows.sort(key=lambda x: int(x.get("last_ts", 0)), reverse=True)
        if limit > 0:
            rows = rows[:limit]
        return rows

    def peer_chat_payload(self, selector: str, limit: int = 120) -> dict:
        selector = selector.strip()
        peer = self.table.resolve(selector) if selector else None
        if peer is not None:
            peer_id = peer.node_id
        else:
            peer_id = selector
        if not peer_id:
            raise ValueError("peer requis")

        with self._chat_lock:
            entries = list(self._chat_history)
        if peer is None:
            has_history = any(str(x.get("peer", "")) == peer_id for x in entries)
            if not has_history and len(peer_id) < 20:
                raise ValueError("pair introuvable")
        messages = [x for x in entries if str(x.get("peer", "")) == peer_id and str(x.get("role", "")) in {"me", "peer"}]
        if limit > 0:
            messages = messages[-limit:]

        resolved = self.table.get(peer_id)
        return {
            "peer_id": peer_id,
            "peer_short": f"{peer_id[:12]}...",
            "trusted": self.trust.is_trusted(peer_id),
            "online": resolved is not None,
            "ip": resolved.ip if resolved is not None else "",
            "tcp_port": resolved.tcp_port if resolved is not None else 0,
            "messages": messages,
        }

    def send_message_to_peer(self, selector: str, text: str) -> dict:
        peer = self.table.resolve(selector.strip())
        if peer is None:
            raise ValueError("pair introuvable (exact ou préfixe unique requis)")
        text = text.strip()
        if not text:
            raise ValueError("texte vide")
        self._ensure_trusted_or_raise(peer, "msg")
        self.tcp.send_secure_message(peer, text)
        self._record_chat("me", text, peer_node_id=peer.node_id)
        return {
            "peer_id": peer.node_id,
            "peer_short": f"{peer.node_id[:12]}...",
            "text": text,
            "ts": int(time.time() * 1000),
        }

    def _on_chat_received(self, from_node_id: str, text: str) -> None:
        self._record_chat("peer", text, peer_node_id=from_node_id)

    def _ai_context_lines(self) -> list[str]:
        out: list[str] = []
        for item in self.chat_history_payload(limit=self.ai_context_messages):
            role = str(item.get("role", "user"))
            peer = str(item.get("peer", ""))
            label = role if not peer else f"{role}:{peer[:12]}"
            out.append(f"{label} > {item.get('text', '')}")
        return out

    def _run_ai_query(self, question: str) -> str:
        question = question.strip()
        if not question:
            return "[AI] Usage: ask <question>"
        self._record_chat("user", question)
        try:
            answer = self.ai.ask(self._ai_context_lines(), question)
        except Exception as exc:
            return f"[AI] {exc}"
        self._record_chat("assistant", answer)
        return f"[AI] {answer}"

    def _trusted_peers(self) -> list[Peer]:
        out: list[Peer] = []
        for item in self.table.to_list():
            node_id = str(item.get("node_id", ""))
            peer = self.table.get(node_id)
            if peer is not None and self.trust.is_trusted(peer.node_id):
                out.append(peer)
        return out

    def _tofu_trust_loop(self) -> None:
        while not self._bg_stop.is_set():
            try:
                for item in self.table.to_list():
                    node_id = str(item.get("node_id", ""))
                    ed25519_pub = str(item.get("ed25519_pub", ""))
                    if not node_id or not ed25519_pub:
                        continue
                    status = self.trust.observe_peer_key(node_id, ed25519_pub, auto_trust=True)
                    if status == "new_trusted":
                        self.log(f"[TRUST/TOFU] Premier contact approuve: {node_id[:12]}...")
                    elif status == "mismatch":
                        self.log(f"[TRUST/TOFU] ALERTE fingerprint mismatch pour {node_id[:12]}... (pair de-trust)")
            except Exception as exc:
                self.log(f"[TRUST/TOFU] Erreur loop: {exc}")
            self._bg_stop.wait(2)

    def _should_auto_replicate(self, file_id: str) -> bool:
        if self.replication_factor <= 1:
            return True
        candidates = {self.identity.node_id}
        for p in self.table.to_list():
            nid = str(p.get("node_id", ""))
            if nid:
                candidates.add(nid)
        scored: list[tuple[int, str]] = []
        for node_id in candidates:
            h = hashlib.sha256(f"{file_id}:{node_id}".encode("utf-8")).digest()
            scored.append((int.from_bytes(h, "big"), node_id))
        scored.sort(key=lambda x: x[0])
        keep = {node for _, node in scored[: min(self.replication_factor, len(scored))]}
        return self.identity.node_id in keep

    def _auto_trust_loop(self) -> None:
        while not self._bg_stop.is_set():
            try:
                for item in self.table.to_list():
                    node_id = str(item.get("node_id", ""))
                    ed25519_pub = str(item.get("ed25519_pub", ""))
                    if not node_id or self.trust.is_trusted(node_id):
                        continue
                    if ed25519_pub:
                        status = self.trust.observe_peer_key(node_id, ed25519_pub, auto_trust=True)
                        if status == "mismatch":
                            self.log(f"[AUTO] Refus trust auto (fingerprint mismatch) {node_id[:12]}...")
                            continue
                        if status == "new_trusted":
                            self.log(f"[AUTO] Trust automatique: {node_id[:12]}...")
                            continue
                    self.trust.trust(node_id)
                    self.log(f"[AUTO] Trust automatique: {node_id[:12]}...")
            except Exception as exc:
                self.log(f"[AUTO] Erreur auto-trust: {exc}")
            self._bg_stop.wait(2)

    def _auto_download_loop(self) -> None:
        while not self._bg_stop.is_set():
            now = time.time()
            try:
                for item in self.transfer.list_manifests():
                    file_id = str(item.get("file_id", ""))
                    if not file_id or file_id in self._auto_download_done:
                        continue
                    if not self._should_auto_replicate(file_id):
                        continue

                    retry_at = self._auto_download_next_try.get(file_id, 0.0)
                    if now < retry_at:
                        continue

                    manifest = self.transfer.load_manifest(file_id)
                    if not manifest:
                        continue

                    nb_chunks = int(manifest.get("nb_chunks", 0))
                    if nb_chunks > 0 and all(self.transfer.has_chunk(file_id, i) for i in range(nb_chunks)):
                        self._auto_download_done.add(file_id)
                        continue

                    selector = str(item.get("source_node_id") or item.get("sender_node_id") or "")
                    peer = self.table.resolve(selector) if selector else None
                    if peer is None:
                        self._auto_download_next_try[file_id] = now + 5
                        continue
                    if not self.trust.is_trusted(peer.node_id):
                        self._auto_download_next_try[file_id] = now + 5
                        continue

                    self.log(f"[AUTO] Download automatique file_id={file_id[:12]}... source={peer.node_id[:12]}...")
                    result = self._run_download(file_id, peer.node_id, "")
                    if result.startswith("[DOWNLOAD] Fichier reconstruit") or result.startswith("[DOWNLOAD] Fichier déjà complet"):
                        self._auto_download_done.add(file_id)
                        self._auto_download_next_try.pop(file_id, None)
                        self.log(result)
                    else:
                        self._auto_download_next_try[file_id] = time.time() + 8
                        self.log(result)
            except Exception as exc:
                self.log(f"[AUTO] Erreur auto-download: {exc}")
            self._bg_stop.wait(2)

    def _auto_send_loop(self) -> None:
        while not self._bg_stop.is_set():
            try:
                peers = self._trusted_peers()
                if not peers:
                    self._bg_stop.wait(2)
                    continue

                for path in sorted(self.auto_send_dir.glob("*")):
                    if not path.is_file():
                        continue
                    try:
                        st = path.stat()
                        stamp = f"{path.resolve()}::{st.st_size}::{st.st_mtime_ns}"
                    except OSError:
                        continue
                    if stamp in self._auto_send_seen:
                        continue

                    manifest = self.transfer.create_manifest_and_chunks(
                        str(path),
                        sender_node_id=self.identity.public_key_raw.hex(),
                    )
                    manifest = sign_manifest(manifest, self.identity)
                    self.transfer.save_manifest(manifest)

                    sent = 0
                    for peer in peers:
                        try:
                            self.tcp.send_manifest(peer, manifest)
                            sent += 1
                        except Exception as exc:
                            self.log(f"[AUTO] Echec envoi manifest vers {peer.node_id[:12]}...: {exc}")

                    if sent > 0:
                        self._auto_send_seen.add(stamp)
                        self.log(
                            f"[AUTO] Partage automatique {path.name} file_id={manifest['file_id'][:12]}... peers={sent}"
                        )
            except Exception as exc:
                self.log(f"[AUTO] Erreur auto-send: {exc}")
            self._bg_stop.wait(2)

    @staticmethod
    def _strip_wrapping_quotes(value: str) -> str:
        out = value.strip()
        while len(out) >= 2 and out[0] == out[-1] and out[0] in {'"', "'"}:
            out = out[1:-1].strip()
        return out

    def _candidate_download_peers(self, selector: str, file_id: str) -> list[Peer]:
        if selector:
            p = self.table.resolve(selector)
            return [p] if p is not None else []

        peers: list[Peer] = []
        manifest = self.transfer.load_manifest(file_id)
        if manifest:
            source_node_id = str(manifest.get("source_node_id") or manifest.get("sender_node_id") or "")
            if source_node_id:
                src = self.table.resolve(source_node_id)
                if src is not None:
                    peers.append(src)

        for item in self.table.to_list():
            node_id = str(item.get("node_id", ""))
            peer = self.table.get(node_id)
            if peer is not None and all(peer.node_id != x.node_id for x in peers):
                peers.append(peer)

        peers.sort(key=lambda p: (-float(getattr(p, "reputation", 1.0)), p.node_id))
        return peers

    def _ensure_trusted_or_raise(self, peer: Peer, context: str) -> None:
        if self.trust.is_trusted(peer.node_id):
            return
        raise ValueError(f"pair non approuvé pour {context}: {peer.node_id[:12]}...")

    def _run_download(self, file_id: str, selector: str, output_path: str) -> str:
        manifest = self.transfer.load_manifest(file_id)
        if manifest is None:
            return "[DOWNLOAD] Manifest introuvable. Il faut d'abord recevoir un MANIFEST."

        peers = self._candidate_download_peers(selector, file_id)
        if not peers:
            return "[DOWNLOAD] Pair source introuvable. Spécifie un node_id/prefix."

        trusted_peers = [p for p in peers if self.trust.is_trusted(p.node_id)]
        if not trusted_peers:
            return "[DOWNLOAD] Aucun pair trusted disponible pour le téléchargement."

        nb_chunks = int(manifest.get("nb_chunks", 0))
        if nb_chunks <= 0:
            return "[DOWNLOAD] Manifest invalide (nb_chunks)"

        self.log(
            f"[DOWNLOAD] Démarrage file_id={file_id} chunks={nb_chunks} peers={len(trusted_peers)} "
            f"(parallel=3, rarest-first)"
        )

        missing = [i for i in range(nb_chunks) if not self.transfer.has_chunk(file_id, i)]
        if not missing:
            out = self.transfer.assemble_file(file_id, output_path if output_path else None)
            return f"[DOWNLOAD] Fichier déjà complet: {out}"

        availability: dict[int, list[Peer]] = {i: [] for i in missing}
        for peer in trusted_peers:
            try:
                have = self.tcp.request_chunk_map(peer, file_id)
            except Exception:
                have = None
            if have is None:
                continue
            for idx in missing:
                if idx in have:
                    availability[idx].append(peer)

        # Fallback: si la cartographie d'un chunk est vide, on tentera tous les pairs trusted.
        for idx in missing:
            if not availability[idx]:
                availability[idx] = list(trusted_peers)

        # Rarest-first: priorité aux chunks disponibles chez le moins de pairs.
        order = sorted(missing, key=lambda i: (len(availability[i]), i))
        done = nb_chunks - len(missing)
        done_lock = threading.Lock()

        def download_one(index: int) -> bool:
            meta = self.transfer.chunk_meta(manifest, index)
            expected_hash = str(meta.get("hash", ""))
            candidates = list(availability[index])
            random.shuffle(candidates)

            for peer in candidates:
                success_for_peer = False
                for _ in range(2):
                    try:
                        resp = self.tcp.request_chunk(peer, file_id, index)
                        if not resp:
                            continue
                        if resp.get("file_id") != file_id or int(resp.get("index", -1)) != index:
                            continue
                        if not verify_chunk_signature(resp, expected_node_id=peer.node_id):
                            continue
                        raw = base64.b64decode(str(resp.get("data", "")).encode("ascii"))
                        if sha256_bytes(raw) != expected_hash:
                            continue
                        self.transfer.store_chunk(file_id, index, raw, expected_hash)
                        success_for_peer = True
                        self.table.record_chunk_result(peer.node_id, True)
                        return True
                    except Exception:
                        continue
                if not success_for_peer:
                    self.table.record_chunk_result(peer.node_id, False)
            return False

        failures: list[int] = []
        workers = max(1, min(3, len(order)))
        with cf.ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(download_one, idx): idx for idx in order}
            for fut in cf.as_completed(futures):
                idx = futures[fut]
                ok = False
                try:
                    ok = bool(fut.result())
                except Exception:
                    ok = False
                if ok:
                    with done_lock:
                        done += 1
                        if done % 10 == 0 or done == nb_chunks:
                            self.log(f"[DOWNLOAD] Progress {done}/{nb_chunks}")
                else:
                    failures.append(idx)

        if failures:
            return f"[DOWNLOAD] Échec chunks: {failures[:8]}{'...' if len(failures) > 8 else ''}"

        out = self.transfer.assemble_file(file_id, output_path if output_path else None)
        return f"[DOWNLOAD] Fichier reconstruit: {out}"

    def run_command(self, raw: str) -> str:
        raw = raw.strip()
        if not raw:
            return ""

        cmd_hint = raw.split(maxsplit=1)[0].lower()

        if cmd_hint == "send":
            parts = raw.split(maxsplit=2)
            if len(parts) < 3:
                return "[CLI] Usage: send <node_id/prefix> <filepath>"
            selector = self._strip_wrapping_quotes(parts[1])
            filepath = self._strip_wrapping_quotes(parts[2])
            peer = self.table.resolve(selector)
            if peer is None:
                return "[CLI] Pair introuvable (exact ou préfixe unique requis)"
            self._ensure_trusted_or_raise(peer, "send")
            manifest = self.transfer.create_manifest_and_chunks(filepath, sender_node_id=self.identity.public_key_raw.hex())
            manifest = sign_manifest(manifest, self.identity)
            self.transfer.save_manifest(manifest)
            self.tcp.send_manifest(peer, manifest)
            return f"[TRANSFER] Manifest signé file_id={manifest['file_id']} chunks={manifest['nb_chunks']}"

        if cmd_hint == "download":
            parts = raw.split(maxsplit=3)
            if len(parts) < 2:
                return "[CLI] Usage: download <file_id> [node_id/prefix] [output_path]"
            file_id = self._strip_wrapping_quotes(parts[1])
            selector = self._strip_wrapping_quotes(parts[2]) if len(parts) >= 3 else ""
            output_path = self._strip_wrapping_quotes(parts[3]) if len(parts) >= 4 else ""
            return self._run_download(file_id, selector, output_path)

        try:
            tokens = shlex.split(raw)
        except ValueError as exc:
            return f"[CLI] Ligne invalide: {exc}"

        cmd = tokens[0].lower()

        if cmd == "help":
            return (
                "whoami | ai-status | auto-status | chat-history | ask </question> | add-peer <node_id> <ip> <port> "
                "[ed25519_pub_b64] | peers | trusted | trust <node> | untrust <node> | files/receive | status | "
                "conversations | chat <node> [limit] | msg <node> <texte> | msg @archipel-ai <question> | send <node> <filepath> | "
                "download <file_id> [node] [output] | quit"
            )

        if cmd == "whoami":
            return json.dumps(
                {
                    "node_id": self.identity.node_id,
                    "ed25519_pub": self.identity.public_key_b64,
                    "tcp_port": self.port,
                },
                indent=2,
            )

        if cmd == "add-peer":
            if len(tokens) < 4:
                return "[CLI] Usage: add-peer <node_id> <ip> <port> [ed25519_pub_b64]"
            node_id = tokens[1].strip().lower()
            ip = tokens[2].strip()
            try:
                tcp_port = int(tokens[3])
            except ValueError:
                return "[CLI] Port invalide"
            if tcp_port <= 0 or tcp_port > 65535:
                return "[CLI] Port invalide"

            ed25519_pub = tokens[4].strip() if len(tokens) >= 5 else ""
            if ed25519_pub:
                try:
                    pub_raw = b64d(ed25519_pub)
                except Exception:
                    return "[CLI] ed25519_pub_b64 invalide"
                if not node_id_matches_pubkey(node_id, pub_raw):
                    return "[CLI] node_id ne correspond pas a la cle publique"

            self.table.upsert(node_id=node_id, ip=ip, tcp_port=tcp_port, ed25519_pub=ed25519_pub)
            return f"[PEER] Pair ajoute: {node_id[:12]}... {ip}:{tcp_port}"

        if cmd == "ai-status":
            return json.dumps(self.ai_status_payload(), indent=2)

        if cmd == "auto-status":
            return json.dumps(self.auto_status_payload(), indent=2)

        if cmd == "chat-history":
            return json.dumps(self.chat_history_payload(limit=30), indent=2)

        if cmd == "conversations":
            return json.dumps(self.conversations_payload(limit=100), indent=2)

        if cmd == "chat":
            if len(tokens) < 2:
                return "[CLI] Usage: chat <node_id/prefix> [limit]"
            selector = tokens[1]
            limit = 120
            if len(tokens) >= 3:
                try:
                    limit = max(1, min(500, int(tokens[2])))
                except ValueError:
                    return "[CLI] limit invalide"
            return json.dumps(self.peer_chat_payload(selector, limit=limit), indent=2)

        if cmd in {"ask", "/ask"}:
            question = " ".join(tokens[1:]) if len(tokens) > 1 else ""
            return self._run_ai_query(question)

        if cmd == "peers":
            return json.dumps(self.peers_payload(), indent=2)

        if cmd == "trusted":
            return json.dumps(self.trust.list_trusted(), indent=2)

        if cmd == "trust":
            if len(tokens) < 2:
                return "[CLI] Usage: trust <node_id/prefix>"
            peer = self.table.resolve(tokens[1])
            if peer is None:
                return "[CLI] Pair introuvable pour trust"
            self.trust.trust(peer.node_id)
            return f"[TRUST] Pair approuvé: {peer.node_id}"

        if cmd == "untrust":
            if len(tokens) < 2:
                return "[CLI] Usage: untrust <node_id/prefix>"
            peer = self.table.resolve(tokens[1])
            if peer is None:
                return "[CLI] Pair introuvable pour untrust"
            self.trust.untrust(peer.node_id)
            return f"[TRUST] Pair retiré: {peer.node_id}"

        if cmd in {"files", "receive"}:
            return json.dumps(self.transfer.list_manifests(), indent=2)

        if cmd == "status":
            s = self.status_snapshot()
            return f"[STATUS] node={s['node_id'][:12]}... peers={s['peers']} trusted={s['trusted']} manifests={s['manifests']} tcp_port={s['tcp_port']}"

        if cmd == "msg":
            if len(tokens) < 3:
                return "[CLI] Usage: msg <node_id/prefix> <texte>"
            if tokens[1].lower() in {"@archipel-ai", "archipel-ai"}:
                question = " ".join(tokens[2:])
                return self._run_ai_query(question)
            text = " ".join(tokens[2:]).strip()
            if text.lower().startswith("@archipel-ai"):
                question = text[len("@archipel-ai") :].strip()
                return self._run_ai_query(question)
            try:
                self.send_message_to_peer(tokens[1], text)
            except ValueError as exc:
                return f"[CLI] {exc}"
            return ""

        if cmd in {"quit", "exit"}:
            return "__QUIT__"

        return "[CLI] Inconnu. Utilise: help"
