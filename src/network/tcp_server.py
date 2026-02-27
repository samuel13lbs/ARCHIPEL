import socket
import threading
import time
from typing import Callable, Optional

from crypto.identity import Identity, b64d, node_id_from_pubkey
from crypto.secure_channel import (
    decrypt_payload,
    encrypt_message,
    encrypt_payload,
    initiator_handshake,
    read_json_line,
    responder_handshake,
    write_json_line,
)
from transfer.manager import TransferManager

from .peer_table import Peer, PeerTable


class TcpServer:
    def __init__(
        self,
        identity: Identity,
        listen_port: int,
        peer_table: PeerTable,
        transfer: TransferManager,
        logger: Callable[[str], None],
        is_trusted: Optional[Callable[[str], bool]] = None,
    ) -> None:
        self.identity = identity
        self.listen_port = listen_port
        self.peer_table = peer_table
        self.transfer = transfer
        self.log = logger
        self.is_trusted = is_trusted if is_trusted is not None else (lambda _node_id: True)
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
            write_json_line(stream, encrypt_message(session, plaintext))
        self.log(f"[MSG] Message chiffré envoyé à {peer.node_id[:12]}... ({peer.ip}:{peer.tcp_port})")

    def send_manifest(self, peer: Peer, manifest: dict) -> None:
        with socket.create_connection((peer.ip, peer.tcp_port), timeout=5.0) as conn:
            conn.settimeout(20)
            session, stream = initiator_handshake(conn, self.identity)
            write_json_line(stream, encrypt_payload(session, manifest))
        self.log(f"[TRANSFER] MANIFEST envoyé à {peer.node_id[:12]}... ({manifest.get('file_id')})")

    def request_chunk(self, peer: Peer, file_id: str, index: int) -> Optional[dict]:
        with socket.create_connection((peer.ip, peer.tcp_port), timeout=5.0) as conn:
            conn.settimeout(20)
            session, stream = initiator_handshake(conn, self.identity)
            req = {"kind": "CHUNK_REQ", "file_id": file_id, "index": index}
            write_json_line(stream, encrypt_payload(session, req))
            reply = read_json_line(stream)
            if reply is None or str(reply.get("type", "")) != "MSG_ENC":
                return None
            payload = decrypt_payload(session, reply)
            if payload.get("kind") != "CHUNK_DATA":
                return None
            return payload

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
        conn.settimeout(30)
        self.log(f"[TCP] Connexion entrante {ip}")
        with conn:
            stream = conn.makefile("rwb")
            while not self._stop.is_set():
                try:
                    msg = read_json_line(stream)
                except OSError:
                    break
                if msg is None:
                    break

                mtype = str(msg.get("type", ""))
                if mtype == "PEER_LIST":
                    self._handle_peer_list(ip, msg)
                    continue

                if mtype == "PING":
                    write_json_line(stream, {"type": "PONG", "timestamp": int(time.time() * 1000)})
                    continue

                if mtype == "HS1":
                    try:
                        session = responder_handshake(stream, self.identity, msg)
                        trust = "trusted" if self.is_trusted(session.remote_node_id) else "untrusted"
                        self.log(f"[HS] Session sécurisée établie avec {session.remote_node_id[:12]}... ({trust})")
                        self._secure_message_loop(stream, session)
                    except OSError:
                        pass
                    except Exception as exc:
                        self.log(f"[HS] Erreur handshake entrant: {exc}")
                    break

                self.log(f"[TCP] Message reçu ({mtype}) depuis {ip}")

    def _secure_message_loop(self, stream, session) -> None:
        while not self._stop.is_set():
            try:
                msg = read_json_line(stream)
            except OSError:
                return
            if msg is None or str(msg.get("type", "")) != "MSG_ENC":
                return
            try:
                payload = decrypt_payload(session, msg)
                kind = str(payload.get("kind", ""))
                remote_trusted = self.is_trusted(session.remote_node_id)

                if kind == "CHAT":
                    if not remote_trusted:
                        self.log(f"[TRUST] CHAT refusé depuis pair non approuvé {session.remote_node_id[:12]}...")
                        continue
                    self.log(f"[MSG] {session.remote_node_id[:12]}... -> {payload.get('text', '')}")
                    write_json_line(stream, {"type": "ACK", "seq": msg.get("seq"), "ts": int(time.time() * 1000)})
                    continue

                if kind == "MANIFEST":
                    self.transfer.save_remote_manifest(payload, source_node_id=session.remote_node_id)
                    self.log(f"[TRANSFER] MANIFEST reçue file_id={payload.get('file_id')} from={session.remote_node_id[:12]}...")
                    continue

                if kind == "CHUNK_REQ":
                    if not remote_trusted:
                        err = {"kind": "ERROR", "code": "NOT_TRUSTED", "file_id": payload.get("file_id"), "index": payload.get("index")}
                        write_json_line(stream, encrypt_payload(session, err))
                        continue
                    file_id = str(payload.get("file_id", ""))
                    index = int(payload.get("index", -1))
                    chunk_payload = self.transfer.build_chunk_data_payload(file_id, index)
                    if chunk_payload is None:
                        err = {"kind": "ERROR", "code": "CHUNK_NOT_FOUND", "file_id": file_id, "index": index}
                        write_json_line(stream, encrypt_payload(session, err))
                    else:
                        write_json_line(stream, encrypt_payload(session, chunk_payload))
                    continue

                if kind == "ERROR":
                    self.log(f"[TRANSFER] Erreur distante: {payload}")
                    continue

                self.log(f"[SECURE] Payload inconnu: {kind}")
            except Exception as exc:
                self.log(f"[SECURE] Erreur payload: {exc}")

    def _handle_peer_list(self, src_ip: str, msg: dict) -> None:
        peers = msg.get("peers", [])
        if not isinstance(peers, list):
            return

        added = 0
        for p in peers:
            try:
                node_id = str(p["node_id"])
                ip = str(p.get("ip", src_ip))
                tcp_port = int(p["tcp_port"])
                ed25519_pub = str(p.get("ed25519_pub", ""))
            except (KeyError, TypeError, ValueError):
                continue

            if node_id == self.identity.node_id:
                continue

            if ed25519_pub:
                try:
                    if node_id_from_pubkey(b64d(ed25519_pub)) != node_id:
                        continue
                except Exception:
                    continue

            self.peer_table.upsert(node_id=node_id, ip=ip, tcp_port=tcp_port, ed25519_pub=ed25519_pub)
            added += 1

        self.log(f"[TCP] PEER_LIST reçue: {added} entrées traitées")
