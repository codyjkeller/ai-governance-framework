"""Shared test fixtures.

These fixtures provide pre-configured scanners, policies, and
test clients that all test modules can reuse.
"""

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ai_governance.audit.logger import AuditLogger
from ai_governance.config import Settings
from ai_governance.policy.loader import load_policy
from ai_governance.scanning.input_scanner import InputScanner
from ai_governance.scanning.output_scanner import OutputScanner


@pytest.fixture
def sample_policy():
    """Load the real YAML policy from the repo."""
    policy_path = Path(__file__).parent.parent / "policies" / "generative_ai_aup.yaml"
    return load_policy(policy_path)


@pytest.fixture
def input_scanner(sample_policy):
    """InputScanner configured with the real policy."""
    return InputScanner(sample_policy)


@pytest.fixture
def output_scanner(sample_policy):
    """OutputScanner configured with the real policy."""
    return OutputScanner(sample_policy)


@pytest.fixture
def audit_logger(tmp_path):
    """AuditLogger writing to a temp directory (cleaned up after each test)."""
    return AuditLogger(tmp_path / "test_audit.jsonl")


@pytest.fixture
def test_settings(tmp_path):
    """Settings configured for testing (no real API key needed for unit tests)."""
    return Settings(
        llm_api_key="sk-test-not-a-real-key-for-unit-tests-only",
        llm_api_url="https://api.openai.com/v1/chat/completions",
        policy_path=Path(__file__).parent.parent / "policies" / "generative_ai_aup.yaml",
        audit_log_path=tmp_path / "test_audit.jsonl",
        rate_limit=0,  # Disable rate limiting in tests
        proxy_api_keys=["test-key-12345"],
    )


@pytest.fixture
def test_client(test_settings):
    """FastAPI TestClient with test settings.

    Uses the application factory to create an isolated app instance.
    """
    # Clear the lru_cache so our test settings take effect
    from ai_governance.config import get_settings
    get_settings.cache_clear()

    from ai_governance.server import create_app
    app = create_app(settings=test_settings)
    return TestClient(app)
