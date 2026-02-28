import argparse
import json
import signal
import threading
import time
from collections import deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from runtime.node_runtime import ArchipelRuntime


class LogBuffer:
    def __init__(self, maxlen: int = 500) -> None:
        self._items = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._seq = 0

    def add(self, line: str) -> None:
        with self._lock:
            self._seq += 1
            self._items.append({"seq": self._seq, "line": line})

    def since(self, seq: int) -> list[dict]:
        with self._lock:
            return [x for x in self._items if x["seq"] > seq]


def build_html() -> str:
    return """<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Archipel Control</title>
  <style>
    :root {
      --bg-1: #0d1b2a;
      --bg-2: #1b263b;
      --panel: rgba(248, 249, 250, 0.93);
      --ink: #0b1320;
      --muted: #53647d;
      --accent: #f77f00;
      --dark: #111827;
      --border: #d9e2ec;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      background: radial-gradient(circle at 10% 10%, #264653, transparent 35%),
                  radial-gradient(circle at 90% 20%, #e76f51, transparent 30%),
                  linear-gradient(135deg, var(--bg-1), var(--bg-2));
      color: var(--ink);
      font-family: "Segoe UI", "Trebuchet MS", sans-serif;
    }
    .container {
      max-width: 1160px;
      margin: 0 auto;
      padding: 16px;
    }
    .panel {
      background: var(--panel);
      border: 1px solid rgba(255, 255, 255, 0.5);
      box-shadow: 0 12px 24px rgba(0,0,0,.18);
      border-radius: 16px;
      padding: 14px;
      margin-bottom: 12px;
    }
    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
    }
    .title { margin: 0; font-size: 24px; }
    .muted { color: var(--muted); }
    .grid {
      display: grid;
      grid-template-columns: 1fr;
      gap: 12px;
    }
    @media (min-width: 900px) {
      .grid { grid-template-columns: 1fr 1fr; }
    }
    .json-box {
      height: 220px;
      overflow-y: auto;
      background: #f1f5f9;
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 12px;
      font-family: Consolas, monospace;
      white-space: pre-wrap;
      margin-top: 8px;
    }
    .log-box {
      height: 260px;
      overflow-y: auto;
      background: var(--dark);
      color: #e5e7eb;
      font-family: Consolas, monospace;
      border-radius: 12px;
      padding: 12px;
      white-space: pre-wrap;
      margin-top: 8px;
    }
    .input-row {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 8px;
      margin-top: 8px;
    }
    input {
      width: 100%;
      padding: 10px 12px;
      border-radius: 10px;
      border: 1px solid #b9c3d0;
      font-size: 14px;
    }
    button {
      border: none;
      border-radius: 10px;
      padding: 10px 14px;
      font-weight: 600;
      cursor: pointer;
    }
    .btn-accent { background: var(--accent); color: #fff; }
    .btn-dark { background: #1f2937; color: #fff; }
  </style>
</head>
<body>
<div class="container">
  <section class="panel">
    <div class="topbar">
      <div>
        <h1 class="title">Archipel Web Console</h1>
        <div id="statusLine" class="muted">Chargement...</div>
      </div>
      <button class="btn-accent" onclick="runCmd('status')">Refresh</button>
    </div>
  </section>

  <section class="grid">
    <div class="panel">
      <strong>Peers</strong>
      <div id="peers" class="json-box"></div>
    </div>
    <div class="panel">
      <strong>Files</strong>
      <div id="files" class="json-box"></div>
    </div>
  </section>

  <section class="panel">
    <strong>Command</strong>
    <div class="input-row">
      <input id="cmd" placeholder="Ex: peers | trust <prefix> | msg <prefix> Bonjour" />
      <button class="btn-dark" onclick="sendCmd()">Run</button>
    </div>
    <div id="cmdOut" class="json-box" style="height:120px"></div>
  </section>

  <section class="panel">
    <strong>Logs</strong>
    <div id="logs" class="log-box"></div>
  </section>
</div>

<script>
let lastSeq = 0;

async function postJson(url, body) {
  const r = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body)
  });
  return await r.json();
}

async function runCmd(c) {
  const out = await postJson('/api/command', {command: c});
  document.getElementById('cmdOut').textContent = out.output || '';
  await refreshPanels();
}

async function sendCmd() {
  const c = document.getElementById('cmd').value.trim();
  if (!c) return;
  await runCmd(c);
}

async function refreshPanels() {
  const s = await (await fetch('/api/state')).json();
  document.getElementById('statusLine').textContent =
    `node=${s.status.node_id.slice(0,12)}... peers=${s.status.peers} trusted=${s.status.trusted} files=${s.status.manifests} tcp=${s.status.tcp_port}`;
  document.getElementById('peers').textContent = JSON.stringify(s.peers, null, 2);
  document.getElementById('files').textContent = JSON.stringify(s.files, null, 2);
}

async function pollLogs() {
  const r = await (await fetch('/api/logs?since=' + lastSeq)).json();
  if (r.items && r.items.length) {
    const box = document.getElementById('logs');
    r.items.forEach(it => {
      box.textContent += it.line + "\\n";
      lastSeq = Math.max(lastSeq, it.seq);
    });
    box.scrollTop = box.scrollHeight;
  }
}

setInterval(pollLogs, 1000);
setInterval(refreshPanels, 3000);
refreshPanels();
pollLogs();
document.getElementById('cmd').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') sendCmd();
});
</script>
</body>
</html>
"""


def main() -> int:
    parser = argparse.ArgumentParser(prog="archipel-web")
    parser.add_argument("--node-port", type=int, default=7777)
    parser.add_argument("--web-port", type=int, default=8080)
    parser.add_argument("--hello-interval", type=int, default=30)
    parser.add_argument("--state-dir", type=str, default=".archipel")
    args = parser.parse_args()

    logs = LogBuffer()

    def logger(msg: str) -> None:
        line = f"{time.strftime('%H:%M:%S')} {msg}"
        print(line, flush=True)
        logs.add(line)

    runtime = ArchipelRuntime(
        port=args.node_port,
        hello_interval=args.hello_interval,
        state_dir=args.state_dir,
        logger=logger,
    )
    runtime.start()

    html = build_html().encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        def _json(self, code: int, payload: dict) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self) -> dict:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0:
                return {}
            raw = self.rfile.read(length)
            return json.loads(raw.decode("utf-8"))

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path == "/":
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
                return

            if parsed.path == "/api/state":
                self._json(
                    HTTPStatus.OK,
                    {
                        "status": runtime.status_snapshot(),
                        "peers": runtime.peers_payload(),
                        "files": runtime.transfer.list_manifests(),
                        "trusted": runtime.trust.list_trusted(),
                    },
                )
                return

            if parsed.path == "/api/logs":
                q = parse_qs(parsed.query)
                since = int(q.get("since", ["0"])[0])
                self._json(HTTPStatus.OK, {"items": logs.since(since)})
                return

            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path == "/api/command":
                try:
                    body = self._read_json()
                    command = str(body.get("command", "")).strip()
                    out = runtime.run_command(command)
                    if out == "__QUIT__":
                        out = "Commande quit ignorée en mode web."
                    self._json(HTTPStatus.OK, {"ok": True, "output": out})
                except Exception as exc:
                    self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "output": f"[ERR] {exc}"})
                return

            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def log_message(self, _format: str, *_args) -> None:
            return

    server = ThreadingHTTPServer(("0.0.0.0", args.web_port), Handler)
    logger(f"[WEB] UI disponible sur http://127.0.0.1:{args.web_port}")

    stop_event = threading.Event()

    def shutdown(*_a) -> None:
        if stop_event.is_set():
            return
        stop_event.set()
        logger("[WEB] Arrêt serveur...")
        server.shutdown()

    signal.signal(signal.SIGINT, shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, shutdown)

    try:
        server.serve_forever()
    finally:
        runtime.stop()
        server.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
