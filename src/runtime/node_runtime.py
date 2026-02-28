import concurrent.futures as cf
import base64
import json
import random
import shlex
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from crypto.identity import b64d, load_or_create_identity, node_id_matches_pubkey
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
    ) -> None:
        self.port = port
        self.hello_interval = hello_interval
        self.state_dir = state_dir
        self.log = logger

        self.profile = f"node-{port}"
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
        self.tcp.start()
        self.discovery.start()

    def stop(self) -> None:
        self.log("[NODE] Arrêt...")
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
                        return True
                    except Exception:
                        continue
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
        try:
            tokens = shlex.split(raw)
        except ValueError as exc:
            return f"[CLI] Ligne invalide: {exc}"

        if not tokens:
            return ""

        cmd = tokens[0].lower()

        if cmd == "help":
            return (
                "whoami | add-peer <node_id> <ip> <port> [ed25519_pub_b64] | peers | trusted | trust <node> | "
                "untrust <node> | files/receive | status | msg <node> <texte> | send <node> <filepath> | "
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
            peer = self.table.resolve(tokens[1])
            if peer is None:
                return "[CLI] Pair introuvable (exact ou préfixe unique requis)"
            self._ensure_trusted_or_raise(peer, "msg")
            text = " ".join(tokens[2:])
            self.tcp.send_secure_message(peer, text)
            return ""

        if cmd == "send":
            if len(tokens) < 3:
                return "[CLI] Usage: send <node_id/prefix> <filepath>"
            peer = self.table.resolve(tokens[1])
            if peer is None:
                return "[CLI] Pair introuvable (exact ou préfixe unique requis)"
            self._ensure_trusted_or_raise(peer, "send")
            filepath = " ".join(tokens[2:])
            manifest = self.transfer.create_manifest_and_chunks(filepath, sender_node_id=self.identity.public_key_raw.hex())
            manifest = sign_manifest(manifest, self.identity)
            self.transfer.save_manifest(manifest)
            self.tcp.send_manifest(peer, manifest)
            return f"[TRANSFER] Manifest signé file_id={manifest['file_id']} chunks={manifest['nb_chunks']}"

        if cmd == "download":
            if len(tokens) < 2:
                return "[CLI] Usage: download <file_id> [node_id/prefix] [output_path]"
            file_id = tokens[1]
            selector = tokens[2] if len(tokens) >= 3 else ""
            output_path = tokens[3] if len(tokens) >= 4 else ""
            return self._run_download(file_id, selector, output_path)

        if cmd in {"quit", "exit"}:
            return "__QUIT__"

        return "[CLI] Inconnu. Utilise: help"
