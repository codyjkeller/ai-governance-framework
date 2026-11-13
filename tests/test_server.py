"""Tests for the FastAPI server endpoints.

Tests the full request lifecycle through the proxy including
authentication, model allowlisting, input scanning, and health check.

NOTE: These tests do NOT call the real upstream LLM. The `upstream`
fixture in conftest.py replaces it with a stand-in for every test.
"""


class TestHealthCheck:
    def test_health_returns_200(self, test_client):
        response = test_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "policy_version" in data
        assert "enforcement_mode" in data


class TestAuthentication:
    def test_rejects_missing_api_key(self, test_client):
        response = test_client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-6-sol",
                "messages": [{"role": "user", "content": "hello"}],
            },
        )
        assert response.status_code == 401

    def test_rejects_invalid_api_key(self, test_client):
        response = test_client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-6-sol",
                "messages": [{"role": "user", "content": "hello"}],
            },
            headers={"X-Governance-API-Key": "wrong-key"},
        )
        assert response.status_code == 401

    def test_accepts_valid_api_key(self, test_client):
        """With a valid key, the request gets past auth and is answered."""
        response = test_client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-6-sol",
                "messages": [{"role": "user", "content": "What is 2+2?"}],
            },
            headers={"X-Governance-API-Key": "test-key-12345"},
        )
        assert response.status_code == 200


class TestModelAllowlist:
    def test_blocks_disallowed_model(self, test_client):
        response = test_client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-3.5-turbo",
                "messages": [{"role": "user", "content": "hello"}],
            },
            headers={"X-Governance-API-Key": "test-key-12345"},
        )
        assert response.status_code == 403
        assert "not approved" in response.json()["detail"]


class TestInputValidation:
    def test_rejects_empty_messages(self, test_client):
        response = test_client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-6-sol",
                "messages": [],
            },
            headers={"X-Governance-API-Key": "test-key-12345"},
        )
        assert response.status_code == 422  # Pydantic validation error

    def test_rejects_no_user_message(self, test_client):
        response = test_client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-6-sol",
                "messages": [{"role": "system", "content": "You are helpful."}],
            },
            headers={"X-Governance-API-Key": "test-key-12345"},
        )
        assert response.status_code == 422

    def test_rejects_invalid_role(self, test_client):
        response = test_client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-6-sol",
                "messages": [{"role": "hacker", "content": "hello"}],
            },
            headers={"X-Governance-API-Key": "test-key-12345"},
        )
        assert response.status_code == 422


class TestInputScanning:
    def test_blocks_prompt_with_ssn(self, test_client):
        response = test_client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-6-sol",
                "messages": [{"role": "user", "content": "My SSN is 123-45-6789"}],
            },
            headers={"X-Governance-API-Key": "test-key-12345"},
        )
        assert response.status_code == 403
        assert "blocked" in response.json()["detail"].lower()

    def test_blocks_prompt_with_aws_key(self, test_client):
        response = test_client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-6-sol",
                "messages": [{"role": "user", "content": "Key: AKIAIOSFODNN7EXAMPLE"}],
            },
            headers={"X-Governance-API-Key": "test-key-12345"},
        )
        assert response.status_code == 403
