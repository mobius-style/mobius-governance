# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) MOBIUS.LLC / Taiko Toeda
"""Generation backend — a thin OpenAI-compatible chat client (pure stdlib).

The governance core is model-independent; only answer *synthesis* needs a model.
This client speaks the OpenAI ``/v1/chat/completions`` shape, so it fronts any
keyless local server (Ollama's ``/v1``, vLLM, llama.cpp, LiteLLM) or an authed
provider. No third-party deps — urllib only — so the package stays light.
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error
from dataclasses import dataclass
from typing import Optional


class BackendError(RuntimeError):
    """Raised when the generation backend is unreachable or returns an error."""


@dataclass
class OpenAICompatBackend:
    """Minimal OpenAI-compatible chat backend.

    Examples:
        Ollama:  base_url="http://127.0.0.1:11434/v1", model="gemma4:12b"
        vLLM:    base_url="http://127.0.0.1:8001/v1",  model="<served-model>"
    """
    base_url: str = "http://127.0.0.1:11434/v1"
    model: str = "gemma4:12b"
    api_key: Optional[str] = None
    timeout: float = 120.0

    def chat(self, prompt: str, **params) -> str:
        """Send a single user turn, return the assistant text. Extra kwargs
        (temperature, max_tokens, ...) pass through to the backend."""
        url = self.base_url.rstrip("/") + "/chat/completions"
        body = {"model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False, **params}
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"),
                                     headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise BackendError(f"backend HTTP {e.code}: {e.read()[:200]!r}") from e
        except urllib.error.URLError as e:
            raise BackendError(f"backend unreachable at {url}: {e.reason}") from e
        try:
            msg = data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as e:
            raise BackendError(f"unexpected backend response: {str(data)[:200]}") from e
        content = (msg.get("content") or "").strip()
        if content:
            return content
        # Reasoning models (e.g. gemma4 via Ollama) can spend the whole token budget
        # in a reasoning channel and return EMPTY content. Surface that channel as a
        # fallback so the answer isn't silently lost — but raise max_tokens for a
        # proper content answer (gemma4 needs ~400+ to finish thinking and answer).
        return (msg.get("reasoning_content") or msg.get("reasoning") or "").strip()
