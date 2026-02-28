import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable

DEFAULT_MODEL = "gemini-2.5-flash"


@dataclass
class GeminiConfig:
    enabled: bool
    api_key: str
    model: str = "gemini-1.5-flash"
    timeout_seconds: float = 15.0


class GeminiClient:
    def __init__(self, config: GeminiConfig, logger: Callable[[str], None]) -> None:
        self._config = config
        self._log = logger

    @classmethod
    def from_env(
        cls,
        enabled: bool,
        logger: Callable[[str], None],
        model: str = DEFAULT_MODEL,
    ) -> "GeminiClient":
        api_key = os.getenv("GEMINI_API_KEY", "").strip()
        env_model = os.getenv("GEMINI_MODEL", "").strip()
        selected_model = env_model if env_model else model
        if selected_model.startswith("models/"):
            selected_model = selected_model[len("models/") :]
        cfg = GeminiConfig(enabled=enabled, api_key=api_key, model=selected_model)
        return cls(cfg, logger)

    def status(self) -> dict:
        return {
            "enabled": self._config.enabled,
            "configured": bool(self._config.api_key),
            "model": self._config.model,
            "endpoint": "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        }

    def ask(self, context_lines: list[str], question: str) -> str:
        if not self._config.enabled:
            raise RuntimeError("IA desactivee (--no-ai)")
        if not self._config.api_key:
            raise RuntimeError("GEMINI_API_KEY absent")

        question = question.strip()
        if not question:
            raise RuntimeError("question vide")

        context = "\n".join(context_lines[-20:])
        prompt = (
            "Tu es l'assistant Archipel. Reponds de facon concise et utile.\n\n"
            f"Contexte conversation:\n{context}\n\n"
            f"Question utilisateur:\n{question}"
        )

        payload = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.3, "maxOutputTokens": 512},
        }
        body = json.dumps(payload).encode("utf-8")

        base = "https://generativelanguage.googleapis.com/v1beta/models/"
        model = urllib.parse.quote(self._config.model, safe="")
        url = f"{base}{model}:generateContent"
        req = urllib.request.Request(url=url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("x-goog-api-key", self._config.api_key)

        try:
            with urllib.request.urlopen(req, timeout=self._config.timeout_seconds) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8", errors="replace")
            except Exception:
                detail = str(exc)
            self._log(f"[AI] HTTP error Gemini: {exc.code}")
            if exc.code == 404:
                raise RuntimeError(
                    f"Modele Gemini introuvable ({self._config.model}). "
                    "Essaye GEMINI_MODEL=gemini-2.5-flash"
                )
            raise RuntimeError(f"Gemini HTTP {exc.code}: {detail[:200]}")
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Gemini indisponible: {exc}")

        try:
            data = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            raise RuntimeError("reponse Gemini invalide (JSON)")

        candidates = data.get("candidates", [])
        if not isinstance(candidates, list) or not candidates:
            raise RuntimeError("aucune reponse Gemini")

        first = candidates[0] if isinstance(candidates[0], dict) else {}
        content = first.get("content", {}) if isinstance(first.get("content", {}), dict) else {}
        parts = content.get("parts", []) if isinstance(content.get("parts", []), list) else []

        fragments: list[str] = []
        for part in parts:
            if isinstance(part, dict):
                text = part.get("text")
                if isinstance(text, str):
                    fragments.append(text)

        out = "\n".join(x.strip() for x in fragments if x.strip()).strip()
        if not out:
            raise RuntimeError("reponse Gemini vide")
        return out
