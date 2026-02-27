# Archipel - Sprint 4 (Python MVP)

Protocole P2P local, chiffré et décentralisé, sans Internet ni serveur central.

## Architecture

- `src/network/`: découverte LAN (UDP multicast), TCP server/client, table de pairs
- `src/crypto/`: identité Ed25519, handshake X25519+HKDF, canal AES-256-GCM
- `src/transfer/`: manifest, chunking, stockage local, reconstruction
- `src/security/`: TrustStore persistant (`trust.json`)
- `src/cli/`: interface de démo

## Primitives cryptographiques

- Identité: `Ed25519`
- Échange de clé session: `X25519`
- Dérivation: `HKDF-SHA256`
- Chiffrement payload: `AES-256-GCM`
- Intégrité fichier/chunks: `SHA-256`

## Réseau

- Découverte: UDP multicast `239.255.42.99:6000`
- Transport applicatif: TCP unicast (port configurable, défaut `7777`)

## Modèle de confiance (Sprint 4)

- TOFU + validation manuelle via commande `trust`
- Les opérations sensibles (`msg`, `send`, `download`, `CHUNK_REQ`) exigent des pairs approuvés.
- Les `MANIFEST` peuvent être reçus sans trust pour découverte de contenu.

## Installation

```powershell
cd c:\Users\USER\OneDrive\Documents\ARCHIPEL
python -m pip install --user cryptography
```

## Démarrage

```powershell
$env:PYTHONPATH="src"
python -m cli.archipel start --port 7777
```

## Lancement auto 3 nœuds (Windows)

```powershell
powershell -ExecutionPolicy Bypass -File .\demo\launch_3_nodes.ps1
```

Options:

```powershell
powershell -ExecutionPolicy Bypass -File .\demo\launch_3_nodes.ps1 -PortA 7777 -PortB 7778 -PortC 7779 -StateDir .archipel
powershell -ExecutionPolicy Bypass -File .\demo\launch_3_nodes.ps1 -DryRun
```

## Commandes CLI

- `peers`
- `trusted`
- `trust <node_id|prefix>`
- `untrust <node_id|prefix>`
- `files`
- `status`
- `msg <node_id|prefix> <texte>`
- `send <node_id|prefix> <filepath>`
- `download <file_id> [node_id|prefix] [output_path]`
- `quit`

## Démo jury (< 5 min)

1. Ouvrir 3 terminaux et démarrer les nœuds ports `7777`, `7778`, `7779`.
2. Sur A et B: `peers`, puis `trust` mutuel.
3. Sur A: `msg <prefix_B> "Hello secure"`.
4. Sur A: `send <prefix_B> <fichier_50MB>`.
5. Sur B: `files`, récupérer `file_id`.
6. Sur B: `download <file_id> <prefix_A>`.
7. Vérifier log `Fichier reconstruit` et `status`.

Scripts de support: `demo/demo_sprint4.ps1`, `demo/launch_3_nodes.ps1`.

## Stockage local

Sous `.archipel/node-<port>/`:

- `ed25519.key`
- `trust.json`
- `transfer/manifests/*.json`
- `transfer/chunks/<file_id>/*.chk`
- `transfer/out/*`

## Limitations connues

- Download mono-source (pas de multi-source parallèle).
- Pas de scheduling rarest-first.
- Pas d’interface web (CLI only).
- Trust manuel local (pas encore de Web-of-Trust distribué).
