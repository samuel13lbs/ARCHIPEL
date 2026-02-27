import json
import socket
import threading
import time
from typing import Callable

from crypto.identity import b64d, node_id_from_pubkey

from .peer_table import PeerTable

MULTICAST_GROUP = "239.255.42.99"
MULTICAST_PORT = 6000


class DiscoveryService:
    def __init__(
        self,
        node_id: str,
        ed25519_pub: str,
        tcp_port: int,
        peer_table: PeerTable,
        logger: Callable[[str], None],
        hello_interval_seconds: int = 30,
    ) -> None:
        self.node_id = node_id
        self.ed25519_pub = ed25519_pub
        self.tcp_port = tcp_port
        self.peer_table = peer_table
        self.log = logger
        self.hello_interval_seconds = hello_interval_seconds
        self._stop = threading.Event()
        self._send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self._send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        self._recv_sock = self._build_recv_socket()

    def _build_recv_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", MULTICAST_PORT))
        mreq = socket.inet_aton(MULTICAST_GROUP) + socket.inet_aton("0.0.0.0")
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(1.0)
        return sock

    def start(self) -> None:
        threading.Thread(target=self._hello_loop, daemon=True).start()
        threading.Thread(target=self._recv_loop, daemon=True).start()
        threading.Thread(target=self._cleanup_loop, daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        self._recv_sock.close()
        self._send_sock.close()

    def _hello_packet(self) -> bytes:
        pkt = {
            "type": "HELLO",
            "node_id": self.node_id,
            "ed25519_pub": self.ed25519_pub,
            "tcp_port": self.tcp_port,
            "timestamp": int(time.time() * 1000),
        }
        return json.dumps(pkt, separators=(",", ":")).encode("utf-8")

    def _hello_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._send_sock.sendto(self._hello_packet(), (MULTICAST_GROUP, MULTICAST_PORT))
                self.log(f"[DISCOVERY] HELLO multicast envoyé ({MULTICAST_GROUP}:{MULTICAST_PORT})")
            except OSError as exc:
                self.log(f"[DISCOVERY] Erreur envoi HELLO: {exc}")
            self._stop.wait(self.hello_interval_seconds)

    def _recv_loop(self) -> None:
        while not self._stop.is_set():
            try:
                raw, addr = self._recv_sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return

            ip, _ = addr
            try:
                msg = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue

            if msg.get("type") != "HELLO":
                continue

            node_id = str(msg.get("node_id", ""))
            ed25519_pub = str(msg.get("ed25519_pub", ""))
            tcp_port = int(msg.get("tcp_port", 0))
            if not node_id or tcp_port <= 0 or not ed25519_pub:
                continue
            if node_id == self.node_id:
                continue

            try:
                if node_id_from_pubkey(b64d(ed25519_pub)) != node_id:
                    continue
            except Exception:
                continue

            self.peer_table.upsert(node_id=node_id, ip=ip, tcp_port=tcp_port, ed25519_pub=ed25519_pub)
            self.log(f"[DISCOVERY] HELLO reçu de {node_id[:12]}... {ip}:{tcp_port}")
            self._send_peer_list(ip, tcp_port)

    def _send_peer_list(self, dest_ip: str, dest_port: int) -> None:
        payload = {
            "type": "PEER_LIST",
            "from": self.node_id,
            "peers": self.peer_table.to_list(),
            "timestamp": int(time.time() * 1000),
        }
        data = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
        try:
            with socket.create_connection((dest_ip, dest_port), timeout=2.0) as conn:
                conn.sendall(data)
            self.log(f"[DISCOVERY] PEER_LIST envoyée à {dest_ip}:{dest_port}")
        except OSError as exc:
            self.log(f"[DISCOVERY] PEER_LIST échec vers {dest_ip}:{dest_port} -> {exc}")

    def _cleanup_loop(self) -> None:
        while not self._stop.is_set():
            removed = self.peer_table.remove_stale()
            for node_id in removed:
                self.log(f"[DISCOVERY] Pair expiré: {node_id[:12]}...")
            self._stop.wait(5)
