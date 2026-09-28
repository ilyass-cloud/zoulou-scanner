"""Tests for repository environment detection (Dockerfile variants)."""

from __future__ import annotations

import pytest

from orchestrator.env_detect import detect_environment


@pytest.mark.parametrize("name", [
    "Dockerfile", "Dockerfile.app", "Dockerfile.db", "Dockerfile.prod", "api.dockerfile",
])
def test_dockerfile_variants_are_detected(tmp_path, name):
    """DVPWA ships Dockerfile.app and Dockerfile.db; neither was recognised."""
    (tmp_path / name).write_text("FROM python:3.12-slim\n", encoding="utf-8")
    assert detect_environment(str(tmp_path)).has_dockerfile is True


def test_no_dockerfile(tmp_path):
    (tmp_path / "dockerfile_notes.md").write_text("not a Dockerfile\n", encoding="utf-8")
    assert detect_environment(str(tmp_path)).has_dockerfile is False
