# Archipel

Protocole P2P local, chiffré et décentralisé, conçu pour fonctionner sans Internet et sans serveur central.

## Description du protocole implémenté

Archipel est un nœud LAN autonome qui combine:
- découverte pair-à-pair via UDP multicast,
- sessions chiffrées E2E sur TCP,
- paquets binaires `ARCP` v1 sur discovery, handshake et tunnel sécurisé (`MAGIC|TYPE|NODE_ID|PAYLOAD_LEN|HMAC`),
- transfert de fichiers chunké avec vérification d'intégrité (hash chunk + signature Ed25519 des `CHUNK_DATA`),
- trust manuel (`trust/untrust`) pour autoriser les opérations sensibles.

Le nœud expose une CLI interactive et une UI Web locale (offline, sans CDN).

## Schéma d'architecture

```text
                 UDP Multicast (239.255.42.99:6000)
     +----------------------------------------------------------+
     |                       Discovery                          |
     +----------------------------------------------------------+
        | HELLO / PEER_LIST                     | HELLO / PEER_LIST
        v                                       v
+-----------------------+               +-----------------------+
| Node A                |   TCP         | Node B                |
| - Ed25519 identity    |<------------->| - Ed25519 identity    |
| - X25519 handshake    |   (HS1/HS2/HS3| - X25519 handshake    |
| - AES-GCM + ARCP v1   |    + MSG_ENC) | - AES-GCM + ARCP v1   |
| - chunk store         |               | - chunk store         |
+-----------------------+               +-----------------------+
        |                                           |
        +---- MANIFEST / CHUNK_REQ / CHUNK_DATA ---+
```

## Choix techniques

- Langage: Python 3.12
- Transport: UDP multicast + TCP unicast
- Interface: CLI + Web locale (HTML/CSS/JS)
- Stockage local: `.archipel/node-<port>/...`

## Primitives cryptographiques et justification

- `Ed25519`: identité des nœuds + signatures (rapide, standard moderne)
- `X25519`: échange de clés éphémères par session (forward secrecy)
- `HKDF-SHA256`: dérivation de clé session
- `AES-256-GCM`: chiffrement authentifié des payloads
- `SHA-256`: intégrité chunks/fichiers + digest de manifest

## Installation (reproductible)

```powershell
cd c:\Users\USER\OneDrive\Documents\ARCHIPEL
python -m pip install --user cryptography
```

## Lancement CLI

```powershell
$env:PYTHONPATH="src"
python -m cli.archipel start --port 7777
# mode offline strict (sans IA): python -m cli.archipel start --port 7777 --no-ai
```

## Lancement Web UI (offline)

```powershell
$env:PYTHONPATH="src"
python -m web.server --node-port 7777 --web-port 8080
# mode offline strict (sans IA): python -m web.server --node-port 7777 --web-port 8080 --no-ai
```

Ouvrir ensuite `http://127.0.0.1:8080`.

## Commandes disponibles (CLI/Web)

- `help`
- `whoami`
- `ai-status`
- `chat-history`
- `ask <question>` (alias: `/ask <question>`)
- `add-peer <node_id> <ip> <port> [ed25519_pub_b64]`
- `peers`
- `trusted`
- `trust <node_id|prefix>`
- `untrust <node_id|prefix>`
- `msg <node_id|prefix> <texte>`
- `msg @archipel-ai <question>`
- `send <node_id|prefix> <filepath>`
- `receive` (alias de `files`)
- `files`
- `download <file_id> [node_id|prefix] [output_path]`
- `status`

## Guide démo (3 cas d'usage)

1. Démarrer 2 ou 3 nœuds (`7777`, `7778`, `7779`).
2. Cas 1, découverte/trust:
   - `peers`
   - `trust <prefix>`
3. Cas 2, message chiffré:
   - `msg <prefix> "Hello secure"`
4. Cas 3, fichier chunké:
   - `send <prefix> <fichier>`
   - côté receveur: `receive` puis `download <file_id> <prefix_source>`

Scripts de démo:
- `demo/launch_3_nodes.ps1`
- `demo/demo_sprint4.ps1`

## Variables d'environnement

Voir `.env.example` pour les valeurs usuelles (ports, state dir).
`ARCHIPEL_CONTROL_HMAC_KEY` (hex 32 bytes) permet de protéger les paquets de contrôle pré-session.
`GEMINI_API_KEY` active l'assistant IA (sinon fallback gracieux).
`GEMINI_MODEL` permet de changer de modèle (défaut: `gemini-2.5-flash`).

## Limites connues

- Download multi-source implémenté (3 workers) avec rarest-first heuristique; optimisation réseau encore possible.
- Keepalive actif implémenté sur sessions sécurisées; instrumentation avancée encore à faire.
- Authentification pré-session des paquets de contrôle (HMAC statique locale) à durcir.
- TOFU automatique non activé (validation via trust manuel uniquement).
- L'IA Gemini dépend d'une connectivité externe + clé API valide.

## Pistes d'amélioration

- Optimisations scheduler (pondération latence/bande passante, priorisation dynamique).
- Métriques de session (RTT, taux retry, débit par pair).
- Réputation des pairs + shared_files dans la peer table (alignement complet cahier).
- Réplication passive configurable des chunks.
- Module IA optionnel (`--no-ai`) conforme cahier.

## Membres et contributions

- `Membre 1` : réseau P2P / discovery
- `Membre 2` : crypto / handshake / trust
- `Membre 3` : chunking / transfert / QA

(Remplacer par les noms réels de l'équipe.)
