"""Tests for the FastAPI server endpoints.

Tests the full request lifecycle through the proxy including
authentication, model allowlisting, input scanning, and health check.

NOTE: These tests do NOT call the real upstream LLM. They test
the governance layers only. The upstream call would need to be
mocked for integration tests (future work).
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
                "model": "gpt-4",
                "messages": [{"role": "user", "content": "hello"}],
            },
        )
        assert response.status_code == 401

    def test_rejects_invalid_api_key(self, test_client):
        response = test_client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4",
                "messages": [{"role": "user", "content": "hello"}],
            },
            headers={"X-Governance-API-Key": "wrong-key"},
        )
        assert response.status_code == 401

    def test_accepts_valid_api_key(self, test_client):
        """With a valid key, the request gets past auth.

        It will still fail because we're not mocking the upstream LLM,
        but it should fail with a 502 (upstream error) not a 401.
        """
        response = test_client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4",
                "messages": [{"role": "user", "content": "What is 2+2?"}],
            },
            headers={"X-Governance-API-Key": "test-key-12345"},
        )
        # Should get past auth — expect 502 because upstream is not mocked
        assert response.status_code != 401


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
                "model": "gpt-4",
                "messages": [],
            },
            headers={"X-Governance-API-Key": "test-key-12345"},
        )
        assert response.status_code == 422  # Pydantic validation error

    def test_rejects_no_user_message(self, test_client):
        response = test_client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4",
                "messages": [{"role": "system", "content": "You are helpful."}],
            },
            headers={"X-Governance-API-Key": "test-key-12345"},
        )
        assert response.status_code == 422

    def test_rejects_invalid_role(self, test_client):
        response = test_client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4",
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
                "model": "gpt-4",
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
                "model": "gpt-4",
                "messages": [{"role": "user", "content": "Key: AKIAIOSFODNN7EXAMPLE"}],
            },
            headers={"X-Governance-API-Key": "test-key-12345"},
        )
        assert response.status_code == 403
