import json
import socket
import threading
import time
from typing import Callable, Optional

from crypto.identity import Identity, b64d, node_id_matches_pubkey
from crypto.secure_channel import (
    initiator_handshake,
    recv_secure_payload,
    responder_handshake,
    send_secure_payload,
)
from network.packet_v1 import CONTROL_HMAC_KEY, PT_HS1, PT_PEER_LIST, decode_tlvs, read_packet
from transfer.chunk_security import sign_chunk_payload
from transfer.manifest_security import manifest_sender_node_id, verify_manifest_signature
from transfer.manager import TransferManager

from .peer_table import Peer, PeerTable

TLV_PEER_LIST_JSON = 0x01


class TcpServer:
    def __init__(
        self,
        identity: Identity,
        listen_port: int,
        peer_table: PeerTable,
        transfer: TransferManager,
        logger: Callable[[str], None],
        is_trusted: Optional[Callable[[str], bool]] = None,
        on_chat: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self.identity = identity
        self.listen_port = listen_port
        self.peer_table = peer_table
        self.transfer = transfer
        self.log = logger
        self.is_trusted = is_trusted if is_trusted is not None else (lambda _node_id: True)
        self.on_chat = on_chat if on_chat is not None else (lambda _node_id, _text: None)
        self._stop = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("0.0.0.0", self.listen_port))
        self._sock.listen(32)
        self._sock.settimeout(1.0)

    def start(self) -> None:
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        self._sock.close()

    def send_secure_message(self, peer: Peer, plaintext: str) -> None:
        with socket.create_connection((peer.ip, peer.tcp_port), timeout=5.0) as conn:
            conn.settimeout(10)
            session, stream = initiator_handshake(conn, self.identity)
            send_secure_payload(stream, session, self.identity.node_id, {"kind": "CHAT", "text": plaintext})
        self.log(f"[MSG] Message chiffré envoyé à {peer.node_id[:12]}... ({peer.ip}:{peer.tcp_port})")

    def send_manifest(self, peer: Peer, manifest: dict) -> None:
        with socket.create_connection((peer.ip, peer.tcp_port), timeout=5.0) as conn:
            conn.settimeout(20)
            session, stream = initiator_handshake(conn, self.identity)
            send_secure_payload(stream, session, self.identity.node_id, manifest)
        self.log(f"[TRANSFER] MANIFEST envoyé à {peer.node_id[:12]}... ({manifest.get('file_id')})")

    def request_chunk(self, peer: Peer, file_id: str, index: int) -> Optional[dict]:
        with socket.create_connection((peer.ip, peer.tcp_port), timeout=5.0) as conn:
            conn.settimeout(20)
            session, stream = initiator_handshake(conn, self.identity)
            req = {"kind": "CHUNK_REQ", "file_id": file_id, "index": index}
            send_secure_payload(stream, session, self.identity.node_id, req)
            payload = recv_secure_payload(stream, session)
            if payload is None or payload.get("kind") != "CHUNK_DATA":
                return None
            return payload

    def request_chunk_map(self, peer: Peer, file_id: str) -> Optional[set[int]]:
        with socket.create_connection((peer.ip, peer.tcp_port), timeout=5.0) as conn:
            conn.settimeout(20)
            session, stream = initiator_handshake(conn, self.identity)
            req = {"kind": "CHUNK_HAVE_REQ", "file_id": file_id}
            send_secure_payload(stream, session, self.identity.node_id, req)
            payload = recv_secure_payload(stream, session)
            if payload is None or payload.get("kind") != "CHUNK_HAVE":
                return None
            indices = payload.get("indices", [])
            if not isinstance(indices, list):
                return None
            out: set[int] = set()
            for x in indices:
                try:
                    out.add(int(x))
                except Exception:
                    continue
            return out

    def _accept_loop(self) -> None:
        self.log(f"[TCP] Écoute sur 0.0.0.0:{self.listen_port}")
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle_conn, args=(conn, addr), daemon=True).start()

    def _handle_conn(self, conn: socket.socket, addr: tuple[str, int]) -> None:
        ip, _ = addr
        conn.settimeout(1.0)
        self.log(f"[TCP] Connexion entrante {ip}")
        with conn:
            stream = conn.makefile("rwb")
            while not self._stop.is_set():
                try:
                    pkt = read_packet(stream, CONTROL_HMAC_KEY)
                except TimeoutError:
                    continue
                except OSError:
                    break
                except Exception:
                    break

                if pkt is None:
                    break

                ptype = int(pkt.get("type", -1))

                if ptype == PT_PEER_LIST:
                    try:
                        tlv_map = {t: v for t, v in decode_tlvs(pkt["payload"])}
                        peers_raw = tlv_map.get(TLV_PEER_LIST_JSON, b"[]")
                        msg = {"peers": json.loads(peers_raw.decode("utf-8"))}
                    except Exception:
                        continue
                    self._handle_peer_list(ip, str(pkt.get("node_id", "")), msg)
                    continue

                if ptype == PT_HS1:
                    try:
                        session = responder_handshake(stream, self.identity, pkt)
                        trust = "trusted" if self.is_trusted(session.remote_node_id) else "untrusted"
                        self.log(f"[HS] Session sécurisée établie avec {session.remote_node_id[:12]}... ({trust})")
                        self._secure_message_loop(stream, session)
                    except OSError:
                        pass
                    except Exception as exc:
                        self.log(f"[HS] Erreur handshake entrant: {exc}")
                    break

                self.log(f"[TCP] Packet contrôle inconnu type=0x{ptype:02x} depuis {ip}")

    def _secure_message_loop(self, stream, session) -> None:
        last_seen = time.time()
        last_ping = 0.0
        while not self._stop.is_set():
            try:
                payload = recv_secure_payload(stream, session)
            except TimeoutError:
                now = time.time()
                if now - last_seen > 45:
                    self.log(f"[TCP] Session expirée (idle timeout) {session.remote_node_id[:12]}...")
                    return
                if now - last_ping >= 15:
                    ping = {"kind": "PING", "ts": int(now * 1000)}
                    send_secure_payload(stream, session, self.identity.node_id, ping)
                    last_ping = now
                continue
            except OSError:
                return
            except Exception as exc:
                self.log(f"[SECURE] Erreur paquet: {exc}")
                return

            if payload is None:
                return

            try:
                last_seen = time.time()
                kind = str(payload.get("kind", ""))
                remote_trusted = self.is_trusted(session.remote_node_id)

                if kind == "CHAT":
                    if not remote_trusted:
                        self.log(f"[TRUST] CHAT refusé depuis pair non approuvé {session.remote_node_id[:12]}...")
                        continue
                    text = str(payload.get("text", ""))
                    self.log(f"[MSG] {session.remote_node_id[:12]}... -> {text}")
                    try:
                        self.on_chat(session.remote_node_id, text)
                    except Exception:
                        pass
                    ack = {"kind": "ACK", "ts": int(time.time() * 1000)}
                    send_secure_payload(stream, session, self.identity.node_id, ack)
                    continue

                if kind == "MANIFEST":
                    if not verify_manifest_signature(payload):
                        self.log(f"[TRANSFER] MANIFEST rejetée (signature invalide) from={session.remote_node_id[:12]}...")
                        continue
                    try:
                        sender_node_id = manifest_sender_node_id(payload)
                    except Exception:
                        self.log(f"[TRANSFER] MANIFEST rejetée (sender_id invalide) from={session.remote_node_id[:12]}...")
                        continue
                    if sender_node_id != session.remote_node_id:
                        self.log(f"[TRANSFER] MANIFEST rejetée (sender mismatch) from={session.remote_node_id[:12]}...")
                        continue

                    saved = dict(payload)
                    saved["sender_node_id"] = sender_node_id
                    self.transfer.save_remote_manifest(saved, source_node_id=session.remote_node_id)
                    file_id = str(payload.get("file_id", ""))
                    if file_id:
                        self.peer_table.note_shared_file(session.remote_node_id, file_id)
                    self.log(f"[TRANSFER] MANIFEST reçue file_id={payload.get('file_id')} from={session.remote_node_id[:12]}...")
                    continue

                if kind == "CHUNK_REQ":
                    if not remote_trusted:
                        err = {"kind": "ERROR", "code": "NOT_TRUSTED", "file_id": payload.get("file_id"), "index": payload.get("index")}
                        send_secure_payload(stream, session, self.identity.node_id, err)
                        continue
                    file_id = str(payload.get("file_id", ""))
                    index = int(payload.get("index", -1))
                    chunk_payload = self.transfer.build_chunk_data_payload(file_id, index)
                    if chunk_payload is None:
                        err = {"kind": "ERROR", "code": "CHUNK_NOT_FOUND", "file_id": file_id, "index": index}
                        send_secure_payload(stream, session, self.identity.node_id, err)
                    else:
                        chunk_payload = sign_chunk_payload(chunk_payload, self.identity)
                        send_secure_payload(stream, session, self.identity.node_id, chunk_payload)
                    continue

                if kind == "CHUNK_HAVE_REQ":
                    if not remote_trusted:
                        err = {"kind": "ERROR", "code": "NOT_TRUSTED", "file_id": payload.get("file_id")}
                        send_secure_payload(stream, session, self.identity.node_id, err)
                        continue
                    file_id = str(payload.get("file_id", ""))
                    indices = self.transfer.available_chunk_indices(file_id)
                    reply = {"kind": "CHUNK_HAVE", "file_id": file_id, "indices": indices}
                    send_secure_payload(stream, session, self.identity.node_id, reply)
                    continue

                if kind == "ERROR":
                    self.log(f"[TRANSFER] Erreur distante: {payload}")
                    continue

                if kind == "PING":
                    pong = {"kind": "PONG", "ts": int(time.time() * 1000)}
                    send_secure_payload(stream, session, self.identity.node_id, pong)
                    continue

                if kind in {"PONG", "ACK"}:
                    continue

                self.log(f"[SECURE] Payload inconnu: {kind}")
            except Exception as exc:
                self.log(f"[SECURE] Erreur payload: {exc}")

    def _handle_peer_list(self, src_ip: str, sender_node_id: str, msg: dict) -> None:
        peers = msg.get("peers", [])
        if not isinstance(peers, list):
            return

        added = 0
        for p in peers:
            try:
                node_id = str(p["node_id"])
                ip = str(p.get("ip", src_ip)).strip()
                tcp_port = int(p["tcp_port"])
                ed25519_pub = str(p.get("ed25519_pub", ""))
                shared_files = p.get("shared_files", [])
            except (KeyError, TypeError, ValueError):
                continue

            if node_id == self.identity.node_id:
                continue

            if ed25519_pub:
                try:
                    if not node_id_matches_pubkey(node_id, b64d(ed25519_pub)):
                        continue
                except Exception:
                    continue

            # If sender announces itself in PEER_LIST, the TCP source IP is authoritative.
            if sender_node_id and node_id == sender_node_id:
                ip = src_ip
            elif not ip:
                ip = src_ip

            self.peer_table.upsert(node_id=node_id, ip=ip, tcp_port=tcp_port, ed25519_pub=ed25519_pub)
            if isinstance(shared_files, list):
                for fid in shared_files:
                    self.peer_table.note_shared_file(node_id, str(fid))
            added += 1

        self.log(f"[TCP] PEER_LIST reçue: {added} entrées traitées")
