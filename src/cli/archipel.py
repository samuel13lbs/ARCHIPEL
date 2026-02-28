import argparse
import signal
import sys
import time

from runtime.node_runtime import ArchipelRuntime


def log(msg: str) -> None:
    print(time.strftime("%H:%M:%S"), msg, flush=True)


def run_start(port: int, hello_interval: int, state_dir: str) -> None:
    runtime = ArchipelRuntime(port=port, hello_interval=hello_interval, state_dir=state_dir, logger=log)
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
        "[CLI] Commandes: help | whoami | add-peer <node_id> <ip> <port> [ed25519_pub_b64] | peers | trusted | "
        "trust <node> | untrust <node> | files | status | msg | send | download | quit"
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

    p_start = sub.add_parser("start", help="Démarrer le nœud CLI")
    p_start.add_argument("--port", type=int, default=7777)
    p_start.add_argument("--hello-interval", type=int, default=30)
    p_start.add_argument("--state-dir", type=str, default=".archipel")

    args = parser.parse_args()

    if args.cmd == "start":
        run_start(port=args.port, hello_interval=args.hello_interval, state_dir=args.state_dir)
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
