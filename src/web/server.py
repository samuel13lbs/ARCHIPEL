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
    def __init__(self, maxlen: int = 800) -> None:
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
  <title>Archipel Console</title>
  <style>
    :root {
      --bg1: #0a2239;
      --bg2: #17324d;
      --panel: rgba(255, 255, 255, 0.95);
      --ink: #0d1b2a;
      --muted: #5f6f82;
      --accent: #ff7f11;
      --ok: #2a9d8f;
      --bad: #b00020;
      --dark: #0f172a;
      --border: #d8e1ea;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      color: var(--ink);
      font-family: "Trebuchet MS", "Segoe UI", sans-serif;
      min-height: 100vh;
      background:
        radial-gradient(circle at 8% 15%, #2b5876 0%, transparent 30%),
        radial-gradient(circle at 92% 8%, #e76f51 0%, transparent 26%),
        linear-gradient(140deg, var(--bg1), var(--bg2));
    }
    .wrap {
      width: min(1220px, 96vw);
      margin: 18px auto 24px;
      display: grid;
      gap: 12px;
    }
    .panel {
      background: var(--panel);
      border: 1px solid rgba(255,255,255,0.65);
      border-radius: 14px;
      box-shadow: 0 12px 24px rgba(0,0,0,.17);
      padding: 14px;
    }
    .top {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      flex-wrap: wrap;
    }
    h1 { margin: 0; font-size: 24px; }
    .muted { color: var(--muted); }
    .pill {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
      margin-right: 6px;
      background: #ecf0f6;
      border: 1px solid #c8d3df;
    }
    .pill.ok { background: #ddf6f2; color: #0f6f63; border-color: #98d8cf; }
    .pill.bad { background: #ffe7eb; color: #8d0e2c; border-color: #ffc8d3; }
    .grid2 {
      display: grid;
      grid-template-columns: 1fr;
      gap: 12px;
    }
    @media (min-width: 980px) {
      .grid2 { grid-template-columns: 1fr 1fr; }
    }
    .grid3 {
      display: grid;
      grid-template-columns: 1fr;
      gap: 12px;
    }
    @media (min-width: 980px) {
      .grid3 { grid-template-columns: repeat(3, 1fr); }
    }
    .label {
      font-size: 13px;
      font-weight: 700;
      margin-bottom: 5px;
    }
    .row {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 8px;
    }
    .row3 {
      display: grid;
      grid-template-columns: 1fr 1fr 1fr auto;
      gap: 8px;
    }
    .row4 {
      display: grid;
      grid-template-columns: 1.2fr 1fr 1fr 1fr auto;
      gap: 8px;
    }
    @media (max-width: 860px) {
      .row3, .row4 { grid-template-columns: 1fr; }
    }
    input, textarea {
      width: 100%;
      border: 1px solid #bdc9d5;
      border-radius: 9px;
      padding: 9px 11px;
      font-size: 14px;
      background: #fff;
      color: var(--ink);
    }
    textarea { min-height: 86px; resize: vertical; }
    button {
      border: none;
      border-radius: 9px;
      padding: 9px 13px;
      font-weight: 700;
      cursor: pointer;
    }
    .btn-main { background: var(--accent); color: #fff; }
    .btn-dark { background: #1f2937; color: #fff; }
    .btn-ok { background: var(--ok); color: #fff; }
    .box {
      background: #eef4f9;
      border: 1px solid var(--border);
      border-radius: 11px;
      padding: 10px;
      font-family: Consolas, "Courier New", monospace;
      white-space: pre-wrap;
      overflow-y: auto;
      max-height: 250px;
      margin-top: 8px;
      font-size: 12px;
    }
    .logbox {
      background: var(--dark);
      color: #e2e8f0;
      border-radius: 11px;
      padding: 10px;
      font-family: Consolas, "Courier New", monospace;
      white-space: pre-wrap;
      overflow-y: auto;
      max-height: 280px;
      margin-top: 8px;
      font-size: 12px;
    }
    .kpi {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-top: 8px;
    }
  </style>
</head>
<body>
<div class="wrap">
  <section class="panel">
    <div class="top">
      <div>
        <h1>Archipel Web Console</h1>
        <div id="statusLine" class="muted">Chargement...</div>
      </div>
      <div>
        <button class="btn-main" onclick="runCmd('status')">Refresh</button>
      </div>
    </div>
    <div class="kpi">
      <span id="aiEnabled" class="pill">AI: ...</span>
      <span id="aiConfigured" class="pill">Key: ...</span>
      <span id="aiModel" class="pill">Model: ...</span>
    </div>
  </section>

  <section class="panel">
    <div class="label">Commande libre</div>
    <div class="row">
      <input id="cmd" placeholder="Ex: peers | trust <prefix> | msg <prefix> bonjour | ask comment tester?" />
      <button class="btn-dark" onclick="sendCmd()">Run</button>
    </div>
    <div id="cmdOut" class="box" style="max-height:160px"></div>
  </section>

  <section class="grid3">
    <div class="panel">
      <div class="label">Trust pair</div>
      <div class="row">
        <input id="trustPeer" placeholder="node_id ou prefix" />
        <button class="btn-ok" onclick="runCmd('trust ' + getv('trustPeer'))">Trust</button>
      </div>
    </div>
    <div class="panel">
      <div class="label">Message pair</div>
      <div class="row3">
        <input id="msgPeer" placeholder="node_id ou prefix" />
        <input id="msgText" placeholder="texte message" />
        <input id="msgHint" placeholder="@archipel-ai ou vide" />
        <button class="btn-main" onclick="sendPeerMsg()">Send</button>
      </div>
    </div>
    <div class="panel">
      <div class="label">Gemini ask</div>
      <div class="row">
        <input id="askText" placeholder="/ask Quel est le plan de test?" />
        <button class="btn-main" onclick="askAi()">Ask</button>
      </div>
    </div>
  </section>

  <section class="panel">
    <div class="label">Transfer</div>
    <div class="row4">
      <input id="sendPeer" placeholder="peer pour send" />
      <input id="sendFile" placeholder="chemin fichier local a envoyer" />
      <input id="dlFileId" placeholder="file_id pour download" />
      <input id="dlPeer" placeholder="peer source (optionnel)" />
      <button class="btn-main" onclick="runTransfer()">Run</button>
    </div>
  </section>

  <section class="grid2">
    <div class="panel">
      <div class="label">Peers</div>
      <div id="peers" class="box"></div>
    </div>
    <div class="panel">
      <div class="label">Files</div>
      <div id="files" class="box"></div>
    </div>
  </section>

  <section class="grid2">
    <div class="panel">
      <div class="label">Chat History</div>
      <div id="chat" class="box"></div>
    </div>
    <div class="panel">
      <div class="label">Logs</div>
      <div id="logs" class="logbox"></div>
    </div>
  </section>
</div>

<script>
let lastSeq = 0;

function getv(id) {
  return (document.getElementById(id).value || '').trim();
}

async function postJson(url, body) {
  const r = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  });
  return await r.json();
}

async function runCmd(command) {
  const cmd = (command || '').trim();
  if (!cmd) return;
  const out = await postJson('/api/command', {command: cmd});
  document.getElementById('cmdOut').textContent = out.output || '';
  await refreshPanels();
}

async function sendCmd() {
  await runCmd(getv('cmd'));
}

async function askAi() {
  const q = getv('askText');
  if (!q) return;
  await runCmd('ask ' + q);
}

async function sendPeerMsg() {
  const peer = getv('msgPeer');
  const txt = getv('msgText');
  const hint = getv('msgHint');
  if (!peer || !txt) return;
  const payload = hint ? (hint + ' ' + txt) : txt;
  await runCmd('msg ' + peer + ' ' + payload);
}

async function runTransfer() {
  const sendPeer = getv('sendPeer');
  const sendFile = getv('sendFile');
  const dlFileId = getv('dlFileId');
  const dlPeer = getv('dlPeer');
  if (sendPeer && sendFile) {
    await runCmd('send ' + sendPeer + ' "' + sendFile + '"');
    return;
  }
  if (dlFileId) {
    const cmd = dlPeer ? ('download ' + dlFileId + ' ' + dlPeer) : ('download ' + dlFileId);
    await runCmd(cmd);
  }
}

function setPill(id, text, ok) {
  const el = document.getElementById(id);
  el.textContent = text;
  el.classList.remove('ok', 'bad');
  el.classList.add(ok ? 'ok' : 'bad');
}

async function refreshPanels() {
  const s = await (await fetch('/api/state')).json();
  document.getElementById('statusLine').textContent =
    'node=' + s.status.node_id.slice(0, 12) + '... peers=' + s.status.peers +
    ' trusted=' + s.status.trusted + ' files=' + s.status.manifests + ' tcp=' + s.status.tcp_port;

  document.getElementById('peers').textContent = JSON.stringify(s.peers, null, 2);
  document.getElementById('files').textContent = JSON.stringify(s.files, null, 2);
  document.getElementById('chat').textContent = JSON.stringify(s.chat, null, 2);

  setPill('aiEnabled', 'AI: ' + (s.ai.enabled ? 'on' : 'off'), !!s.ai.enabled);
  setPill('aiConfigured', 'Key: ' + (s.ai.configured ? 'ok' : 'missing'), !!s.ai.configured);
  const model = s.ai.model || 'n/a';
  const modelOk = s.ai.enabled && s.ai.configured;
  setPill('aiModel', 'Model: ' + model, modelOk);
}

async function pollLogs() {
  const r = await (await fetch('/api/logs?since=' + lastSeq)).json();
  if (r.items && r.items.length) {
    const box = document.getElementById('logs');
    r.items.forEach((it) => {
      box.textContent += it.line + '\\n';
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
document.getElementById('askText').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') askAi();
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
    parser.add_argument("--no-ai", action="store_true", help="Desactiver l'integration Gemini")
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
        ai_enabled=not args.no_ai,
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
                        "chat": runtime.chat_history_payload(limit=30),
                        "ai": runtime.ai_status_payload(),
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
                        out = "Commande quit ignoree en mode web."
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
        logger("[WEB] Arret serveur...")
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

