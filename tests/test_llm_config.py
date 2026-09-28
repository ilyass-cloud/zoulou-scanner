"""Tests for the LLM budget: one default, and it reaches the wire.

The defect these pin down was silent by construction. `LLMConfig.max_tokens`
defaulted to 4096 and `LMStudioClient.__init__` to 2048, yet no run ever used
2048: `build_client_from_config` always passes the configured value, so the
client's default was dead code. A dead default cannot be caught by any test of
behaviour — it never executes — which is exactly why the two drifted. The
defence is therefore structural (a single constant) and the tests below assert
the structure, not just the current numbers.
"""

from __future__ import annotations

import json

import pytest

from orchestrator.config import LLMConfig, OrchestratorConfig
from orchestrator.llm_client import (
    DEFAULT_MAX_TOKENS,
    LMStudioClient,
    build_client_from_config,
)


def test_the_two_defaults_are_the_same_object_not_merely_equal():
    """Equality would pass again the day someone edits one of two literals.

    Identity of source is the property that matters: both sides must read the
    same constant.
    """
    assert LLMConfig().max_tokens == DEFAULT_MAX_TOKENS
    assert LMStudioClient().max_tokens == DEFAULT_MAX_TOKENS
    assert LLMConfig.model_fields["max_tokens"].default is DEFAULT_MAX_TOKENS


def test_the_client_default_and_the_config_default_agree():
    assert LMStudioClient().max_tokens == LLMConfig().max_tokens


def test_a_configured_budget_reaches_the_client():
    cfg = OrchestratorConfig()
    cfg.llm.max_tokens = 777
    assert build_client_from_config(cfg).max_tokens == 777


def test_the_configured_budget_is_what_goes_on_the_wire(monkeypatch):
    """The end the defect was invisible at: what the server is actually told."""
    sent = {}

    def fake_post(self, url, payload):
        sent.update(payload)
        return "ok"

    monkeypatch.setattr(LMStudioClient, "_post", fake_post)

    cfg = OrchestratorConfig()
    cfg.llm.max_tokens = 1234
    build_client_from_config(cfg).generate("hello")

    assert sent["max_tokens"] == 1234


def test_the_default_budget_is_what_goes_on_the_wire(monkeypatch):
    sent = {}
    monkeypatch.setattr(
        LMStudioClient, "_post", lambda self, url, payload: sent.update(payload) or "ok"
    )
    LMStudioClient().generate("hello")
    assert sent["max_tokens"] == DEFAULT_MAX_TOKENS
