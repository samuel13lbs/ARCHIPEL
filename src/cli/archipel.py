import argparse
import base64
import json
import os
import shlex
import signal
import sys
import time

from crypto.identity import load_or_create_identity
from network.discovery import DiscoveryService
from network.peer_table import Peer, PeerTable
from network.tcp_server import TcpServer
from security.trust_store import TrustStore
from transfer.manager import TransferManager, sha256_bytes


def log(msg: str) -> None:
    print(time.strftime("%H:%M:%S"), msg, flush=True)


def resolve_download_peer(selector: str, table: PeerTable, transfer: TransferManager, file_id: str):
    if selector:
        return table.resolve(selector)

    manifest = transfer.load_manifest(file_id)
    if not manifest:
        return None
    source_node_id = str(manifest.get("source_node_id") or manifest.get("sender_id") or "")
    if not source_node_id:
        return None
    return table.resolve(source_node_id)


def ensure_trusted_or_log(peer: Peer, trust: TrustStore, context: str) -> bool:
    if trust.is_trusted(peer.node_id):
        return True
    log(f"[TRUST] Pair non approuvé pour {context}: {peer.node_id[:12]}... Utilise: trust {peer.node_id[:12]}")
    return False


def run_download(
    tcp: TcpServer,
    table: PeerTable,
    transfer: TransferManager,
    trust: TrustStore,
    file_id: str,
    selector: str,
    output_path: str,
) -> None:
    manifest = transfer.load_manifest(file_id)
    if manifest is None:
        log("[DOWNLOAD] Manifest introuvable. Il faut d'abord recevoir un MANIFEST.")
        return

    peer = resolve_download_peer(selector, table, transfer, file_id)
    if peer is None:
        log("[DOWNLOAD] Pair source introuvable. Spécifie un node_id/prefix.")
        return

    if not ensure_trusted_or_log(peer, trust, "download"):
        return

    nb_chunks = int(manifest.get("nb_chunks", 0))
    if nb_chunks <= 0:
        log("[DOWNLOAD] Manifest invalide (nb_chunks)")
        return

    log(f"[DOWNLOAD] Démarrage file_id={file_id} chunks={nb_chunks} source={peer.node_id[:12]}...")

    done = 0
    for i in range(nb_chunks):
        meta = transfer.chunk_meta(manifest, i)
        expected_hash = str(meta.get("hash", ""))
        if transfer.has_chunk(file_id, i):
            done += 1
            continue

        ok = False
        for attempt in range(1, 4):
            try:
                resp = tcp.request_chunk(peer, file_id, i)
                if not resp:
                    continue
                if resp.get("file_id") != file_id or int(resp.get("index", -1)) != i:
                    continue
                raw = base64.b64decode(str(resp.get("data", "")).encode("ascii"))
                if sha256_bytes(raw) != expected_hash:
                    continue
                transfer.store_chunk(file_id, i, raw, expected_hash)
                ok = True
                done += 1
                if done % 10 == 0 or done == nb_chunks:
                    log(f"[DOWNLOAD] Progress {done}/{nb_chunks}")
                break
            except Exception:
                continue

            if attempt < 3:
                time.sleep(0.2)

        if not ok:
            log(f"[DOWNLOAD] Échec chunk {i}. Téléchargement interrompu.")
            return

    try:
        out = transfer.assemble_file(file_id, output_path if output_path else None)
        log(f"[DOWNLOAD] Fichier reconstruit: {out}")
    except Exception as exc:
        log(f"[DOWNLOAD] Erreur assemblage: {exc}")


def run_start(port: int, hello_interval: int, state_dir: str) -> None:
    profile = f"node-{port}"
    identity = load_or_create_identity(state_dir, profile=profile)
    trust = TrustStore(state_dir, profile=profile)
    table = PeerTable(ttl_seconds=90)
    transfer = TransferManager(state_dir, profile=profile)

    tcp = TcpServer(
        identity=identity,
        listen_port=port,
        peer_table=table,
        transfer=transfer,
        logger=log,
        is_trusted=trust.is_trusted,
    )
    discovery = DiscoveryService(
        node_id=identity.node_id,
        ed25519_pub=identity.public_key_b64,
        tcp_port=port,
        peer_table=table,
        logger=log,
        hello_interval_seconds=hello_interval,
    )

    log(f"[NODE] node_id={identity.node_id}")
    log(f"[NODE] pubkey_b64={identity.public_key_b64}")
    tcp.start()
    discovery.start()

    stopping = False

    def shutdown(*_: object) -> None:
        nonlocal stopping
        if stopping:
            return
        stopping = True
        log("[NODE] Arrêt...")
        discovery.stop()
        tcp.stop()

    signal.signal(signal.SIGINT, shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, shutdown)

    log("[CLI] Commandes: peers | trusted | trust <node> | untrust <node> | files | status | msg <node> <texte> | send <node> <filepath> | download <file_id> [node] [output] | quit")
    while not stopping:
        try:
            raw = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            shutdown()
            break

        if not raw:
            continue

        try:
            tokens = shlex.split(raw)
        except ValueError as exc:
            log(f"[CLI] Ligne invalide: {exc}")
            continue

        if not tokens:
            continue

        cmd = tokens[0].lower()

        if cmd == "peers":
            peers = table.to_list()
            for p in peers:
                p["trusted"] = trust.is_trusted(str(p.get("node_id", "")))
            print(json.dumps(peers, indent=2), flush=True)
            continue

        if cmd == "trusted":
            print(json.dumps(trust.list_trusted(), indent=2), flush=True)
            continue

        if cmd == "trust":
            if len(tokens) < 2:
                log("[CLI] Usage: trust <node_id/prefix>")
                continue
            peer = table.resolve(tokens[1])
            if peer is None:
                log("[CLI] Pair introuvable pour trust")
                continue
            trust.trust(peer.node_id)
            log(f"[TRUST] Pair approuvé: {peer.node_id}")
            continue

        if cmd == "untrust":
            if len(tokens) < 2:
                log("[CLI] Usage: untrust <node_id/prefix>")
                continue
            peer = table.resolve(tokens[1])
            if peer is None:
                log("[CLI] Pair introuvable pour untrust")
                continue
            trust.untrust(peer.node_id)
            log(f"[TRUST] Pair retiré: {peer.node_id}")
            continue

        if cmd == "files":
            print(json.dumps(transfer.list_manifests(), indent=2), flush=True)
            continue

        if cmd == "status":
            peers = table.to_list()
            files = transfer.list_manifests()
            trusted_count = sum(1 for p in peers if trust.is_trusted(str(p.get("node_id", ""))))
            log(f"[STATUS] peers={len(peers)} trusted={trusted_count} manifests={len(files)} tcp_port={port}")
            continue

        if cmd == "msg":
            if len(tokens) < 3:
                log("[CLI] Usage: msg <node_id/prefix> <texte>")
                continue
            selector = tokens[1]
            text = " ".join(tokens[2:])
            peer = table.resolve(selector)
            if peer is None:
                log("[CLI] Pair introuvable (exact ou préfixe unique requis)")
                continue
            if not ensure_trusted_or_log(peer, trust, "msg"):
                continue
            try:
                tcp.send_secure_message(peer, text)
            except Exception as exc:
                log(f"[MSG] Envoi échoué: {exc}")
            continue

        if cmd == "send":
            if len(tokens) < 3:
                log("[CLI] Usage: send <node_id/prefix> <filepath>")
                continue
            selector = tokens[1]
            filepath = " ".join(tokens[2:])
            peer = table.resolve(selector)
            if peer is None:
                log("[CLI] Pair introuvable (exact ou préfixe unique requis)")
                continue
            if not ensure_trusted_or_log(peer, trust, "send"):
                continue
            try:
                manifest = transfer.create_manifest_and_chunks(filepath, sender_node_id=identity.node_id)
                tcp.send_manifest(peer, manifest)
                log(f"[TRANSFER] Manifest local créé file_id={manifest['file_id']} chunks={manifest['nb_chunks']}")
            except Exception as exc:
                log(f"[TRANSFER] Envoi manifest échoué: {exc}")
            continue

        if cmd == "download":
            if len(tokens) < 2:
                log("[CLI] Usage: download <file_id> [node_id/prefix] [output_path]")
                continue
            file_id = tokens[1]
            selector = tokens[2] if len(tokens) >= 3 else ""
            output_path = tokens[3] if len(tokens) >= 4 else ""
            run_download(tcp, table, transfer, trust, file_id, selector, output_path)
            continue

        if cmd in {"quit", "exit"}:
            shutdown()
            continue

        log("[CLI] Inconnu. Utilise: peers | trusted | trust | untrust | files | status | msg | send | download | quit")


def main() -> int:
    parser = argparse.ArgumentParser(prog="archipel")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_start = sub.add_parser("start", help="Démarrer le nœud Sprint 4")
    p_start.add_argument("--port", type=int, default=int(os.getenv("ARCHIPEL_PORT", "7777")))
    p_start.add_argument("--hello-interval", type=int, default=30)
    p_start.add_argument("--state-dir", type=str, default=os.getenv("ARCHIPEL_STATE_DIR", ".archipel"))

    args = parser.parse_args()

    if args.cmd == "start":
        run_start(port=args.port, hello_interval=args.hello_interval, state_dir=args.state_dir)
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
