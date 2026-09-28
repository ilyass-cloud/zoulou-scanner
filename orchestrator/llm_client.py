"""LM Studio HTTP client.

Communicates with a locally running LM Studio server via its OpenAI-compatible
REST API.  No external SaaS calls are made.

Usage:
    client = LMStudioClient(base_url="http://localhost:1234", model="local-model")
    text = client.generate("Summarise these findings: ...")
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

try:
    import urllib.request as _urllib_request
    import urllib.error as _urllib_error
except ImportError:
    pass  # stdlib – always available

log = logging.getLogger(__name__)

#: Budget de sortie par défaut, en jetons.
#
# Cette constante est l'unique définition du défaut : ``LLMConfig.max_tokens``
# l'importe, et ``build_client_from_config`` transmet toujours la valeur de
# configuration au client. Le paramètre ci-dessous n'est donc atteint que par
# un appel direct à ``LMStudioClient`` — un chemin de test ou de script. Les
# deux valeurs ont divergé (4096 côté configuration, 2048 côté client) sans que
# rien ne le signale, précisément parce que la seconde était morte ; une seule
# définition rend la divergence impossible plutôt que détectable.
DEFAULT_MAX_TOKENS = 4096

_DEFAULT_SYSTEM_PROMPT = (
    "You are a security analyst assistant. "
    "You receive structured vulnerability findings and produce concise, "
    "accurate security analysis. "
    "You MUST ground every statement in the provided evidence. "
    "If evidence is missing or insufficient, you MUST state: "
    "'insufficient evidence to assess this finding.' "
    "Do NOT invent CVEs, package names, or exploit details."
)


class LMStudioClient:
    """Thin HTTP client for LM Studio's OpenAI-compatible /v1/chat/completions endpoint."""

    def __init__(
        self,
        base_url: str = "http://localhost:1234",
        model: str = "local-model",
        timeout_seconds: int = 120,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        temperature: float = 0.2,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout_seconds
        self.max_tokens = max_tokens
        self.temperature = temperature

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        json_schema: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Send a prompt to LM Studio and return the response text.

        Args:
            prompt: The user message / instruction.
            system_prompt: Override the default system prompt.
            json_schema: Optional JSON schema for structured output
                         (passed as response_format if supported).

        Returns:
            The model's response as a plain string.

        Raises:
            RuntimeError: If the HTTP request fails or the response is malformed.
        """
        url = f"{self.base_url}/v1/chat/completions"
        messages = [
            {"role": "system", "content": system_prompt or _DEFAULT_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "stream": False,
        }
        if json_schema:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": json_schema,
            }

        text = self._post(url, payload)

        # Some local "reasoning" models return an empty `content` when a
        # structured-output schema is imposed (the visible answer is suppressed
        # in favour of internal reasoning). Retry once as free-form text so the
        # pipeline still gets usable output.
        if json_schema and not text.strip():
            log.debug("llm_client: empty content with json_schema – retrying as plain text")
            payload.pop("response_format", None)
            text = self._post(url, payload)

        log.debug("llm_client: received %d chars", len(text))
        return text

    def _post(self, url: str, payload: Dict[str, Any]) -> str:
        """POST a chat-completion payload and return the message content."""
        body = json.dumps(payload).encode("utf-8")
        req = _urllib_request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with _urllib_request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
        except _urllib_error.URLError as exc:
            raise RuntimeError(
                f"LM Studio request failed: {exc}\n"
                f"Is LM Studio running at {self.base_url}?"
            ) from exc

        try:
            data = json.loads(raw)
            return data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"Unexpected LM Studio response format: {exc}\nRaw: {raw[:500]}"
            ) from exc


def build_client_from_config(cfg) -> LMStudioClient:
    """Construct an LMStudioClient from an OrchestratorConfig."""
    llm_cfg = cfg.llm
    return LMStudioClient(
        base_url=llm_cfg.base_url,
        model=llm_cfg.model,
        timeout_seconds=llm_cfg.timeout_seconds,
        max_tokens=llm_cfg.max_tokens,
        temperature=llm_cfg.temperature,
    )

