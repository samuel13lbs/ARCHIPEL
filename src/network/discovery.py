import base64
import json
import socket
import struct
import threading
import time
from typing import Callable

from crypto.identity import node_id_matches_pubkey
from network.packet_v1 import (
    CONTROL_HMAC_KEY,
    PT_HELLO,
    PT_PEER_LIST,
    decode_tlvs,
    encode_tlvs,
    pack_packet,
    unpack_packet,
)

from .peer_table import PeerTable

MULTICAST_GROUP = "239.255.42.99"
MULTICAST_PORT = 6000

TLV_HELLO_TCP_PORT = 0x01
TLV_HELLO_ED25519_PUB = 0x02
TLV_HELLO_TS = 0x03
TLV_PEER_LIST_JSON = 0x01


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
        try:
            pub_raw = base64.b64decode(self.ed25519_pub.encode("ascii"))
        except Exception:
            pub_raw = b""

        payload = encode_tlvs(
            [
                (TLV_HELLO_TCP_PORT, struct.pack(">I", self.tcp_port)),
                (TLV_HELLO_ED25519_PUB, pub_raw),
                (TLV_HELLO_TS, int(time.time() * 1000).to_bytes(8, "big")),
            ]
        )
        return pack_packet(PT_HELLO, self.node_id, payload, CONTROL_HMAC_KEY)

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
                raw, addr = self._recv_sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return

            ip, _ = addr
            try:
                pkt = unpack_packet(raw, CONTROL_HMAC_KEY)
            except Exception:
                continue

            if pkt.get("type") != PT_HELLO:
                continue

            try:
                data = {t: v for t, v in decode_tlvs(pkt["payload"])}
                node_id = str(pkt["node_id"])
                ed25519_pub_raw = data[TLV_HELLO_ED25519_PUB]
                tcp_port = struct.unpack(">I", data[TLV_HELLO_TCP_PORT])[0]
            except Exception:
                continue

            if not node_id or tcp_port <= 0 or not ed25519_pub_raw:
                continue
            if node_id == self.node_id:
                continue

            if not node_id_matches_pubkey(node_id, ed25519_pub_raw):
                continue

            ed25519_pub_b64 = base64.b64encode(ed25519_pub_raw).decode("ascii")
            self.peer_table.upsert(node_id=node_id, ip=ip, tcp_port=tcp_port, ed25519_pub=ed25519_pub_b64)
            self.log(f"[DISCOVERY] HELLO reçu de {node_id[:12]}... {ip}:{tcp_port}")
            self._send_peer_list(ip, tcp_port)

    def _send_peer_list(self, dest_ip: str, dest_port: int) -> None:
        peers_json = json.dumps(self.peer_table.to_list(), separators=(",", ":")).encode("utf-8")
        payload = encode_tlvs([(TLV_PEER_LIST_JSON, peers_json)])
        data = pack_packet(PT_PEER_LIST, self.node_id, payload, CONTROL_HMAC_KEY)
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
