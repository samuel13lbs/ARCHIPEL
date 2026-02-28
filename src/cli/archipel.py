import argparse
import os
import signal
import sys
import time

from runtime.node_runtime import ArchipelRuntime


def log(msg: str) -> None:
    print(time.strftime("%H:%M:%S"), msg, flush=True)


def run_start(
    port: int,
    hello_interval: int,
    state_dir: str,
    no_ai: bool,
    auto: bool,
    auto_send_dir: str,
    no_tofu: bool,
    replication_factor: int,
) -> None:
    runtime = ArchipelRuntime(
        port=port,
        hello_interval=hello_interval,
        state_dir=state_dir,
        logger=log,
        ai_enabled=not no_ai,
        tofu_auto=not no_tofu,
        auto_mode=auto,
        auto_send_dir=auto_send_dir,
        replication_factor=replication_factor,
    )
    runtime.start()

    stopping = False

    def shutdown(*_: object) -> None:
        nonlocal stopping
        if stopping:
            return
        stopping = True
        runtime.stop()

    signal.signal(signal.SIGINT, shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, shutdown)

    log(
        "[CLI] Commandes: help | whoami | ai-status | auto-status | chat-history | ask | add-peer <node_id> <ip> <port> "
        "[ed25519_pub_b64] | peers | trusted | trust <node> | untrust <node> | files | status | msg | send | "
        "download | quit"
    )
    while not stopping:
        try:
            raw = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            shutdown()
            break

        if not raw:
            continue

        try:
            out = runtime.run_command(raw)
            if out == "__QUIT__":
                shutdown()
                break
            if out:
                print(out, flush=True)
        except Exception as exc:
            log(f"[ERR] {exc}")


def main() -> int:
    parser = argparse.ArgumentParser(prog="archipel")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_start = sub.add_parser("start", help="Demarrer le noeud CLI")
    p_start.add_argument("--port", type=int, default=7777)
    p_start.add_argument("--hello-interval", type=int, default=30)
    p_start.add_argument("--state-dir", type=str, default=".archipel")
    p_start.add_argument("--no-ai", action="store_true", help="Desactiver l'integration Gemini")
    p_start.add_argument("--no-tofu", action="store_true", help="Desactiver le trust TOFU automatique")
    p_start.add_argument("--auto", action="store_true", help="Activer auto trust/download/share sans intervention")
    p_start.add_argument("--auto-send-dir", type=str, default="", help="Dossier a partager automatiquement (mode --auto)")
    p_start.add_argument(
        "--replication-factor",
        type=int,
        default=max(1, int(os.getenv("ARCHIPEL_REPLICATION_FACTOR", "1"))),
        help="Facteur de replication passive (mode --auto)",
    )

    args = parser.parse_args()

    if args.cmd == "start":
        run_start(
            port=args.port,
            hello_interval=args.hello_interval,
            state_dir=args.state_dir,
            no_ai=args.no_ai,
            auto=args.auto,
            auto_send_dir=args.auto_send_dir,
            no_tofu=args.no_tofu,
            replication_factor=max(1, int(args.replication_factor)),
        )
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())

