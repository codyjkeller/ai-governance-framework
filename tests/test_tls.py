"""Tests for transport security: the proxy either serves HTTPS itself or is
told that something in front of it does. Otherwise it does not start."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ai_governance import server
from ai_governance.config import Settings
from ai_governance.server import ConfigurationError, create_app, tls_options

POLICY = Path(__file__).parent.parent / "policies" / "generative_ai_aup.yaml"


@pytest.fixture
def cert_files(tmp_path):
    cert, key = tmp_path / "tls.crt", tmp_path / "tls.key"
    cert.write_text("placeholder certificate")
    key.write_text("placeholder key")
    return cert, key


def settings(tmp_path, **overrides):
    values = {
        "llm_api_key": "sk-test-not-a-real-key-for-unit-tests-only",
        "policy_path": POLICY,
        "audit_log_path": tmp_path / "audit.jsonl",
        "rate_limit": 0,
        "proxy_api_keys": ["app:k1"],
        "audit_hmac_key": "test-signing-key-not-a-real-secret-000000",
    }
    values.update(overrides)
    return Settings(**values)


class TestStartup:
    def test_refuses_to_start_without_tls(self, tmp_path):
        with pytest.raises(ConfigurationError, match="No TLS is configured"):
            create_app(settings=settings(tmp_path))

    def test_starts_when_tls_is_handled_in_front(self, tmp_path):
        client = TestClient(create_app(settings=settings(tmp_path, tls_terminated_upstream=True)))
        assert client.get("/health").json()["tls"] == "upstream"

    def test_starts_with_a_certificate_and_key(self, tmp_path, cert_files):
        cert, key = cert_files
        app = create_app(settings=settings(tmp_path, tls_cert_file=cert, tls_key_file=key))
        client = TestClient(app, base_url="https://testserver")
        response = client.get("/health")
        assert response.json()["tls"] == "native"
        assert response.headers["strict-transport-security"] == "max-age=31536000"

    def test_dev_flag_allows_no_tls_and_says_so(self, tmp_path):
        client = TestClient(create_app(settings=settings(tmp_path, allow_insecure_dev=True)))
        assert client.get("/health").json()["tls"] == "none"


class TestNativeTlsRejectsPlainHttp:
    def test_plain_http_request_is_refused(self, tmp_path, cert_files):
        cert, key = cert_files
        app = create_app(settings=settings(tmp_path, tls_cert_file=cert, tls_key_file=key))
        response = TestClient(app, base_url="http://testserver").get("/health")
        assert response.status_code == 400
        assert response.json() == {"detail": "HTTPS is required."}


class TestSettings:
    def test_certificate_without_key_is_rejected(self, tmp_path, cert_files):
        with pytest.raises(ValueError, match="both TLS_CERT_FILE and TLS_KEY_FILE"):
            settings(tmp_path, tls_cert_file=cert_files[0])

    def test_missing_certificate_file_is_rejected(self, tmp_path, cert_files):
        with pytest.raises(ValueError, match="TLS file not found"):
            settings(tmp_path, tls_cert_file=tmp_path / "nope.crt", tls_key_file=cert_files[1])

    def test_empty_env_values_mean_not_set(self, monkeypatch):
        monkeypatch.setenv("LLM_API_KEY", "sk-test-not-a-real-key-for-unit-tests-only")
        monkeypatch.setenv("TLS_CERT_FILE", "")
        monkeypatch.setenv("TLS_KEY_FILE", "")
        assert Settings().serves_tls is False

    def test_upstream_provider_must_be_https(self, tmp_path):
        with pytest.raises(ValueError, match="LLM_API_URL must start with https://"):
            settings(tmp_path, llm_api_url="http://api.example.com/v1/chat/completions")
        assert settings(tmp_path, llm_api_url="http://localhost:11434/v1/chat/completions")


class TestServerStartOptions:
    def test_no_tls_options_when_handled_in_front(self, tmp_path):
        assert tls_options(settings(tmp_path, tls_terminated_upstream=True)) == {}

    def test_main_starts_uvicorn_with_tls_port_and_workers(self, tmp_path, cert_files, monkeypatch):
        import uvicorn

        cert, key = cert_files
        configured = settings(tmp_path, tls_cert_file=cert, tls_key_file=key, port=8443, workers=3)
        started = {}
        monkeypatch.setattr(server, "get_settings", lambda: configured)
        monkeypatch.setattr(uvicorn, "run", lambda app, **options: started.update(options, app=app))
        server.main()
        assert started["app"] == "ai_governance.server:app"
        assert (started["port"], started["workers"]) == (8443, 3)
        assert started["ssl_certfile"] == str(cert) and started["ssl_keyfile"] == str(key)
        assert started["ssl_ciphers"] == "ECDHE+AESGCM"
