import argparse
import json
import os
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
<html lang=\"fr\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Archipel UI</title>
  <style>
    :root {
      --bg: #0b1f3a;
      --bg-soft: #12345f;
      --panel: #f5f8fc;
      --line: #d0dae7;
      --ink: #132338;
      --muted: #5e7189;
      --primary: #ef7d21;
      --ok: #198754;
      --bad: #b02a37;
      --log: #111b2a;
      --nav: #0f2a4d;
      --nav-active: #ef7d21;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      color: var(--ink);
      font-family: \"Segoe UI\", \"Trebuchet MS\", sans-serif;
      background:
        radial-gradient(circle at 88% 10%, #244d7f 0%, transparent 28%),
        radial-gradient(circle at 12% 12%, #365e8d 0%, transparent 24%),
        linear-gradient(140deg, var(--bg), var(--bg-soft));
    }
    .shell {
      width: min(1280px, 96vw);
      margin: 14px auto 18px;
      display: grid;
      gap: 12px;
    }
    .panel {
      background: var(--panel);
      border: 1px solid rgba(255, 255, 255, 0.6);
      border-radius: 14px;
      box-shadow: 0 12px 24px rgba(0, 0, 0, 0.16);
      padding: 14px;
    }
    .header {
      display: flex;
      justify-content: space-between;
      gap: 10px;
      align-items: center;
      flex-wrap: wrap;
    }
    h1 {
      margin: 0;
      font-size: 24px;
      letter-spacing: 0.2px;
    }
    .muted { color: var(--muted); }
    .badge {
      display: inline-block;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 4px 10px;
      font-size: 12px;
      font-weight: 700;
      background: #ebf0f7;
      margin-right: 6px;
    }
    .badge.ok {
      border-color: #7fddb3;
      background: #dff8ec;
      color: #0f6b44;
    }
    .badge.bad {
      border-color: #f2a9b2;
      background: #fde8eb;
      color: #8b1f2a;
    }
    .nav {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      background: var(--nav);
      border-radius: 12px;
      padding: 8px;
    }
    .tab {
      border: none;
      border-radius: 8px;
      padding: 9px 14px;
      background: rgba(255, 255, 255, 0.1);
      color: #dce8f7;
      font-weight: 700;
      cursor: pointer;
    }
    .tab.active {
      background: var(--nav-active);
      color: #fff;
    }
    .page { display: none; }
    .page.active { display: block; }

    .grid2 {
      display: grid;
      gap: 12px;
      grid-template-columns: 1fr;
    }
    .grid3 {
      display: grid;
      gap: 12px;
      grid-template-columns: 1fr;
    }
    @media (min-width: 980px) {
      .grid2 { grid-template-columns: 1fr 1fr; }
      .grid3 { grid-template-columns: repeat(3, 1fr); }
    }

    .label {
      font-size: 13px;
      font-weight: 700;
      margin-bottom: 6px;
    }
    .row {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 8px;
    }
    .row3 {
      display: grid;
      grid-template-columns: 1fr 1fr auto;
      gap: 8px;
    }
    .row4 {
      display: grid;
      grid-template-columns: 1fr 1fr 1fr auto;
      gap: 8px;
    }
    @media (max-width: 860px) {
      .row3, .row4 { grid-template-columns: 1fr; }
    }

    input, textarea {
      width: 100%;
      border: 1px solid #bdc9d7;
      border-radius: 8px;
      padding: 9px 10px;
      font-size: 14px;
      background: #fff;
      color: var(--ink);
    }
    textarea { min-height: 80px; resize: vertical; }

    button {
      border: none;
      border-radius: 8px;
      padding: 9px 12px;
      font-weight: 700;
      cursor: pointer;
    }
    .btn-main { background: var(--primary); color: #fff; }
    .btn-dark { background: #1f2937; color: #fff; }
    .btn-ok { background: var(--ok); color: #fff; }
    .btn-bad { background: var(--bad); color: #fff; }

    .box {
      margin-top: 8px;
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 10px;
      background: #edf3f9;
      font-family: Consolas, \"Courier New\", monospace;
      font-size: 12px;
      white-space: pre-wrap;
      overflow-y: auto;
      max-height: 300px;
    }
    .logs {
      background: var(--log);
      color: #e4ebf6;
      border-radius: 10px;
      padding: 10px;
      font-family: Consolas, \"Courier New\", monospace;
      font-size: 12px;
      white-space: pre-wrap;
      overflow-y: auto;
      max-height: 330px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      background: #fff;
      border: 1px solid var(--line);
      border-radius: 10px;
      overflow: hidden;
    }
    th, td {
      text-align: left;
      border-bottom: 1px solid #e6edf6;
      padding: 8px 10px;
      vertical-align: top;
      word-break: break-word;
    }
    th {
      background: #ebf2fb;
      font-weight: 700;
      color: #243a57;
    }
    .kpis {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 8px;
    }
  </style>
</head>
<body>
<div class=\"shell\">
  <section class=\"panel\">
    <div class=\"header\">
      <div>
        <h1>Archipel Control Center</h1>
        <div id=\"statusLine\" class=\"muted\">Chargement...</div>
      </div>
      <div>
        <button class=\"btn-main\" onclick=\"refreshAll()\">Refresh</button>
      </div>
    </div>
    <div class=\"kpis\">
      <span id=\"aiEnabled\" class=\"badge\">AI: ...</span>
      <span id=\"aiConfigured\" class=\"badge\">Key: ...</span>
      <span id=\"aiModel\" class=\"badge\">Model: ...</span>
      <span id=\"autoMode\" class=\"badge\">Auto: ...</span>
    </div>
  </section>

  <nav class=\"nav panel\">
    <button class=\"tab\" data-page=\"dashboard\" onclick=\"setPage('dashboard')\">Dashboard</button>
    <button class=\"tab\" data-page=\"messages\" onclick=\"setPage('messages')\">Messages</button>
    <button class=\"tab\" data-page=\"files\" onclick=\"setPage('files')\">Fichiers</button>
    <button class=\"tab\" data-page=\"peers\" onclick=\"setPage('peers')\">Peers</button>
  </nav>

  <section id=\"page-dashboard\" class=\"panel page\">
    <div class=\"label\">Commande libre</div>
    <div class=\"row\">
      <input id=\"cmd\" placeholder=\"Ex: status | peers | trust <prefix> | ai-status\" />
      <button class=\"btn-dark\" onclick=\"sendCmd()\">Run</button>
    </div>
    <div id=\"cmdOut\" class=\"box\" style=\"max-height:180px\"></div>

    <div class=\"grid2\" style=\"margin-top:12px\">
      <div>
        <div class=\"label\">Question Gemini</div>
        <div class=\"row\">
          <input id=\"askText\" placeholder=\"ask explique mon statut reseau\" />
          <button class=\"btn-main\" onclick=\"askAi()\">Ask</button>
        </div>
      </div>
      <div>
        <div class=\"label\">Historique chat global</div>
        <div id=\"chat\" class=\"box\"></div>
      </div>
    </div>

    <div style=\"margin-top:12px\">
      <div class=\"row\">
        <div class=\"label\" style=\"margin-bottom:0\">Logs temps réel</div>
        <button id=\"toggleLogsBtn\" class=\"btn-dark\" onclick=\"toggleLogs()\">Cacher logs</button>
      </div>
      <div id=\"logs\" class=\"logs\"></div>
    </div>
  </section>

  <section id=\"page-messages\" class=\"panel page\">
    <div class=\"grid2\">
      <div>
        <div class=\"label\">Envoyer un message</div>
        <div class=\"row3\">
          <input id=\"msgPeer\" placeholder=\"node_id ou prefix\" />
          <input id=\"msgText\" placeholder=\"message\" />
          <button class=\"btn-main\" onclick=\"sendPeerMsg()\">Send</button>
        </div>
        <div class=\"muted\" style=\"margin-top:6px\">Le pair doit etre trusted pour envoyer.</div>
      </div>
      <div>
        <div class=\"label\">Trust management</div>
        <div class=\"row3\">
          <input id=\"trustPeer\" placeholder=\"node_id ou prefix\" />
          <button class=\"btn-ok\" onclick=\"runCmd('trust ' + getv('trustPeer'))\">Trust</button>
          <button class=\"btn-bad\" onclick=\"runCmd('untrust ' + getv('trustPeer'))\">Untrust</button>
        </div>
      </div>
    </div>

    <div style=\"margin-top:12px\">
      <div class=\"label\">Chat history (JSON)</div>
      <div id=\"chatMessages\" class=\"box\" style=\"max-height:420px\"></div>
    </div>
  </section>

  <section id=\"page-files\" class=\"panel page\">
    <div class=\"grid2\">
      <div>
        <div class=\"label\">Envoyer un fichier</div>
        <div class=\"row3\">
          <input id=\"sendPeer\" placeholder=\"node_id ou prefix\" />
          <input id=\"sendFile\" placeholder=\"chemin local complet\" />
          <button class=\"btn-main\" onclick=\"sendFileToPeer()\">Send</button>
        </div>
      </div>
      <div>
        <div class=\"label\">Télécharger un fichier</div>
        <div class=\"row4\">
          <input id=\"dlFileId\" placeholder=\"file_id\" />
          <input id=\"dlPeer\" placeholder=\"peer source (optionnel)\" />
          <input id=\"dlOut\" placeholder=\"output_path (optionnel)\" />
          <button class=\"btn-main\" onclick=\"downloadFile()\">Download</button>
        </div>
      </div>
    </div>

    <div style=\"margin-top:12px\">
      <div class=\"label\">Manifests disponibles</div>
      <div id=\"files\" class=\"box\" style=\"max-height:420px\"></div>
    </div>
  </section>

  <section id=\"page-peers\" class=\"panel page\">
    <div class=\"grid2\">
      <div>
        <div class=\"label\">Ajouter peer manuellement</div>
        <div class=\"row4\">
          <input id=\"apNode\" placeholder=\"node_id\" />
          <input id=\"apIp\" placeholder=\"ip\" />
          <input id=\"apPort\" placeholder=\"port\" />
          <button class=\"btn-main\" onclick=\"addPeerManual()\">Add peer</button>
        </div>
        <div class=\"muted\" style=\"margin-top:6px\">Utilise cette option si multicast LAN est bloqué.</div>
      </div>
      <div>
        <div class=\"label\">Trusted nodes</div>
        <div id=\"trusted\" class=\"box\" style=\"max-height:170px\"></div>
      </div>
    </div>

    <div style=\"margin-top:12px\">
      <div class=\"label\">Peers disponibles (avec ports)</div>
      <div style=\"overflow:auto; margin-top:8px\">
        <table>
          <thead>
            <tr>
              <th>Node ID</th>
              <th>IP</th>
              <th>Port</th>
              <th>Trusted</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody id=\"peersRows\">
            <tr><td colspan=\"5\" class=\"muted\">Chargement...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </section>
</div>

<script>
let lastSeq = 0;
let appState = null;
let logsVisible = true;
const pages = ['dashboard', 'messages', 'files', 'peers'];

function getv(id) {
  return (document.getElementById(id).value || '').trim();
}

function esc(v) {
  return String(v || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function setBadge(id, text, ok) {
  const el = document.getElementById(id);
  el.textContent = text;
  el.classList.remove('ok', 'bad');
  el.classList.add(ok ? 'ok' : 'bad');
}

function setPage(page) {
  const selected = pages.includes(page) ? page : 'dashboard';
  pages.forEach((name) => {
    const sec = document.getElementById('page-' + name);
    if (sec) sec.classList.toggle('active', name === selected);
  });
  document.querySelectorAll('.tab').forEach((el) => {
    el.classList.toggle('active', el.dataset.page === selected);
  });
  if (window.location.hash !== '#' + selected) {
    window.location.hash = selected;
  }
}

function setLogsVisibility(visible) {
  logsVisible = !!visible;
  const box = document.getElementById('logs');
  const btn = document.getElementById('toggleLogsBtn');
  if (!box || !btn) return;
  box.style.display = logsVisible ? 'block' : 'none';
  btn.textContent = logsVisible ? 'Cacher logs' : 'Afficher logs';
}

function toggleLogs() {
  setLogsVisibility(!logsVisible);
}

function pageFromHash() {
  const raw = (window.location.hash || '').replace('#', '').trim().toLowerCase();
  return pages.includes(raw) ? raw : 'dashboard';
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
  await refreshAll();
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
  if (!peer || !txt) return;
  await runCmd('msg ' + peer + ' ' + txt);
}

async function sendFileToPeer() {
  const peer = getv('sendPeer');
  const path = getv('sendFile');
  if (!peer || !path) return;
  await runCmd('send ' + peer + ' "' + path + '"');
}

async function downloadFile() {
  const id = getv('dlFileId');
  const peer = getv('dlPeer');
  const out = getv('dlOut');
  if (!id) return;
  let cmd = 'download ' + id;
  if (peer) cmd += ' ' + peer;
  if (out) cmd += ' "' + out + '"';
  await runCmd(cmd);
}

async function addPeerManual() {
  const node = getv('apNode');
  const ip = getv('apIp');
  const port = getv('apPort');
  if (!node || !ip || !port) return;
  await runCmd('add-peer ' + node + ' ' + ip + ' ' + port);
}

function formatTs(epochSecs) {
  const n = Number(epochSecs || 0);
  if (!n) return '';
  const d = new Date(n * 1000);
  return d.toLocaleString();
}

function renderPeers(peers) {
  const body = document.getElementById('peersRows');
  if (!Array.isArray(peers) || !peers.length) {
    body.innerHTML = '<tr><td colspan=\"5\" class=\"muted\">Aucun peer detecte</td></tr>';
    return;
  }
  body.innerHTML = peers.map((p) => {
    const node = esc(p.node_id || '');
    const ip = esc(p.ip || '');
    const port = esc(p.tcp_port || '');
    const trusted = p.trusted ? 'yes' : 'no';
    const last = formatTs(p.last_seen);
    return '<tr>' +
      '<td>' + node + '</td>' +
      '<td>' + ip + '</td>' +
      '<td>' + port + '</td>' +
      '<td>' + trusted + '</td>' +
      '<td>' + esc(last) + '</td>' +
      '</tr>';
  }).join('');
}

function renderTrusted(trusted) {
  document.getElementById('trusted').textContent = JSON.stringify(trusted || [], null, 2);
}

function renderFiles(files) {
  document.getElementById('files').textContent = JSON.stringify(files || [], null, 2);
}

function renderChat(chat) {
  const txt = JSON.stringify(chat || [], null, 2);
  document.getElementById('chat').textContent = txt;
  document.getElementById('chatMessages').textContent = txt;
}

function renderHeader(state) {
  const s = state.status || {};
  const ai = state.ai || {};
  const auto = state.auto || {};
  const nodeId = String(s.node_id || '');
  document.getElementById('statusLine').textContent =
    'node=' + nodeId.slice(0, 12) + '... peers=' + (s.peers || 0) +
    ' trusted=' + (s.trusted || 0) + ' files=' + (s.manifests || 0) +
    ' tcp=' + (s.tcp_port || '') + ' auto=' + (auto.enabled ? 'on' : 'off');

  setBadge('aiEnabled', 'AI: ' + (ai.enabled ? 'on' : 'off'), !!ai.enabled);
  setBadge('aiConfigured', 'Key: ' + (ai.configured ? 'ok' : 'missing'), !!ai.configured);
  setBadge('aiModel', 'Model: ' + (ai.model || 'n/a'), !!(ai.enabled && ai.configured));
  setBadge('autoMode', 'Auto: ' + (auto.enabled ? 'on' : 'off'), !!auto.enabled);
}

async function refreshState() {
  const s = await (await fetch('/api/state')).json();
  appState = s;
  renderHeader(s);
  renderPeers(s.peers || []);
  renderTrusted(s.trusted || []);
  renderFiles(s.files || []);
  renderChat(s.chat || []);
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

async function refreshAll() {
  await refreshState();
  await pollLogs();
}

window.addEventListener('hashchange', () => setPage(pageFromHash()));

setInterval(refreshState, 3000);
setInterval(pollLogs, 1000);
refreshAll();
setPage(pageFromHash());
setLogsVisibility(true);

document.getElementById('cmd').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') sendCmd();
});

document.getElementById('askText').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') askAi();
});

document.getElementById('msgText').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') sendPeerMsg();
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
    parser.add_argument("--no-tofu", action="store_true", help="Desactiver le trust TOFU automatique")
    parser.add_argument("--auto", action="store_true", help="Activer auto trust/download/share")
    parser.add_argument("--auto-send-dir", type=str, default="", help="Dossier auto-share (mode --auto)")
    parser.add_argument(
        "--replication-factor",
        type=int,
        default=max(1, int(os.getenv("ARCHIPEL_REPLICATION_FACTOR", "1"))),
        help="Facteur de replication passive (mode --auto)",
    )
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
        tofu_auto=not args.no_tofu,
        auto_mode=args.auto,
        auto_send_dir=args.auto_send_dir,
        replication_factor=max(1, int(args.replication_factor)),
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
                        "auto": runtime.auto_status_payload(),
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
