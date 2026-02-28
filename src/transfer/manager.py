import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Optional

from transfer.manifest_security import manifest_sender_node_id


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


class TransferManager:
    def __init__(self, base_dir: str, profile: str) -> None:
        self.root = Path(base_dir) / profile / "transfer"
        self.manifests_dir = self.root / "manifests"
        self.chunks_dir = self.root / "chunks"
        self.out_dir = self.root / "out"
        ensure_dir(self.manifests_dir)
        ensure_dir(self.chunks_dir)
        ensure_dir(self.out_dir)

    def _manifest_path(self, file_id: str) -> Path:
        return self.manifests_dir / f"{file_id}.json"

    def _chunk_path(self, file_id: str, index: int) -> Path:
        d = self.chunks_dir / file_id
        ensure_dir(d)
        return d / f"{index:08d}.chk"

    def available_chunk_indices(self, file_id: str) -> list[int]:
        d = self.chunks_dir / file_id
        if not d.exists():
            return []
        out: list[int] = []
        for p in d.glob("*.chk"):
            try:
                out.append(int(p.stem))
            except ValueError:
                continue
        out.sort()
        return out

    def save_manifest(self, manifest: dict[str, Any]) -> None:
        file_id = str(manifest.get("file_id", ""))
        if not file_id:
            raise ValueError("manifest sans file_id")
        self._manifest_path(file_id).write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    def create_manifest_and_chunks(self, file_path: str, sender_node_id: str, chunk_size: int = 524288) -> dict[str, Any]:
        p = Path(file_path)
        data = p.read_bytes()
        file_id = sha256_bytes(data)
        size = len(data)

        chunks_meta = []
        index = 0
        for offset in range(0, size, chunk_size):
            part = data[offset : offset + chunk_size]
            chash = sha256_bytes(part)
            self._chunk_path(file_id, index).write_bytes(part)
            chunks_meta.append({"index": index, "hash": chash, "size": len(part)})
            index += 1

        manifest = {
            "kind": "MANIFEST",
            "file_id": file_id,
            "filename": p.name,
            "size": size,
            "chunk_size": chunk_size,
            "nb_chunks": len(chunks_meta),
            "chunks": chunks_meta,
            "sender_id": sender_node_id,
        }
        self.save_manifest(manifest)
        return manifest

    def save_remote_manifest(self, manifest: dict[str, Any], source_node_id: str) -> None:
        file_id = str(manifest.get("file_id", ""))
        if not file_id:
            raise ValueError("manifest sans file_id")

        saved = dict(manifest)
        saved["source_node_id"] = source_node_id
        try:
            saved["sender_node_id"] = manifest_sender_node_id(manifest)
        except Exception:
            saved["sender_node_id"] = ""
        self._manifest_path(file_id).write_text(json.dumps(saved, indent=2), encoding="utf-8")

    def load_manifest(self, file_id: str) -> Optional[dict[str, Any]]:
        p = self._manifest_path(file_id)
        if not p.exists():
            return None
        return json.loads(p.read_text(encoding="utf-8"))

    def list_manifests(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for p in sorted(self.manifests_dir.glob("*.json")):
            try:
                m = json.loads(p.read_text(encoding="utf-8"))
                out.append(
                    {
                        "file_id": m.get("file_id"),
                        "filename": m.get("filename"),
                        "size": m.get("size"),
                        "nb_chunks": m.get("nb_chunks"),
                        "sender_id": m.get("sender_id"),
                        "sender_node_id": m.get("sender_node_id", ""),
                        "source_node_id": m.get("source_node_id", m.get("sender_node_id", "")),
                    }
                )
            except Exception:
                continue
        return out

    def has_chunk(self, file_id: str, index: int) -> bool:
        return self._chunk_path(file_id, index).exists()

    def read_chunk(self, file_id: str, index: int) -> Optional[bytes]:
        p = self._chunk_path(file_id, index)
        if not p.exists():
            return None
        return p.read_bytes()

    def store_chunk(self, file_id: str, index: int, data: bytes, expected_hash: str) -> None:
        if sha256_bytes(data) != expected_hash:
            raise ValueError("hash chunk invalide")
        self._chunk_path(file_id, index).write_bytes(data)

    def build_chunk_data_payload(self, file_id: str, index: int) -> Optional[dict[str, Any]]:
        raw = self.read_chunk(file_id, index)
        if raw is None:
            return None
        return {
            "kind": "CHUNK_DATA",
            "file_id": file_id,
            "index": index,
            "data": base64.b64encode(raw).decode("ascii"),
            "hash": sha256_bytes(raw),
            "size": len(raw),
        }

    def chunk_meta(self, manifest: dict[str, Any], index: int) -> dict[str, Any]:
        chunks = manifest.get("chunks", [])
        if not isinstance(chunks, list) or index < 0 or index >= len(chunks):
            raise ValueError("index chunk invalide")
        return chunks[index]

    def assemble_file(self, file_id: str, output_path: Optional[str] = None) -> str:
        manifest = self.load_manifest(file_id)
        if manifest is None:
            raise ValueError("manifest introuvable")

        nb_chunks = int(manifest["nb_chunks"])
        parts: list[bytes] = []
        for i in range(nb_chunks):
            part = self.read_chunk(file_id, i)
            if part is None:
                raise ValueError(f"chunk manquant: {i}")
            parts.append(part)

        data = b"".join(parts)
        if sha256_bytes(data) != file_id:
            raise ValueError("hash fichier final invalide")

        filename = str(manifest.get("filename", f"{file_id}.bin"))
        target = Path(output_path) if output_path else (self.out_dir / filename)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return str(target)
