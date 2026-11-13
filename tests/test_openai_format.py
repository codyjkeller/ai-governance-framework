"""Tests for handling the full OpenAI chat format.

The proxy must pass a real client's request through unchanged, scan every
piece of text in it, and scan everything that comes back.
"""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ai_governance.config import Settings
from ai_governance.policy.loader import PolicyError, load_policy
from ai_governance.scanning.input_scanner import InputScanner
from ai_governance.scanning.payload import scan_request_payload
from ai_governance.server import create_app

POLICY = Path(__file__).parent.parent / "policies" / "generative_ai_aup.yaml"
HEADERS = {"X-Governance-API-Key": "k1"}
USER = {"role": "user", "content": "What's the weather in Paris?"}
TOOL = {
    "type": "function",
    "function": {
        "name": "get_weather",
        "description": "Look up the weather for a city.",
        "parameters": {"type": "object", "properties": {"city": {"type": "string"}}},
    },
}
TOOL_CALL = {
    "role": "assistant",
    "content": None,
    "tool_calls": [
        {"id": "call_A10", "type": "function", "function": {"name": "get_weather", "arguments": '{"city": "Paris"}'}}
    ],
}


def make_client(tmp_path, policy_path=POLICY, **overrides):
    values = {
        "llm_api_key": "sk-test-not-a-real-key-for-unit-tests-only",
        "policy_path": policy_path,
        "audit_log_path": tmp_path / "audit.jsonl",
        "rate_limit": 0,
        "proxy_api_keys": ["app:k1"],
        "audit_hmac_key": "test-signing-key-not-a-real-secret-000000",
        "tls_terminated_upstream": True,
    }
    values.update(overrides)
    return TestClient(create_app(settings=Settings(**values)))


def chat(client, messages, **extra):
    return client.post(
        "/v1/chat/completions", json={"model": "gpt-6-sol", "messages": messages, **extra}, headers=HEADERS
    )


def audit_entries(tmp_path):
    return [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]


def permissive_policy(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text(POLICY.read_text().replace("allow_non_text_content: false", "allow_non_text_content: true"))
    return path


class TestRequestsPassThroughUnchanged:
    def test_a_clean_request_is_forwarded_exactly_as_sent(self, tmp_path, upstream):
        body = {
            "model": "gpt-6-sol",
            "messages": [
                {"role": "developer", "content": "Be brief."},
                USER,
                TOOL_CALL,
                {"role": "tool", "tool_call_id": "call_A10", "content": "18C and sunny"},
            ],
            "max_tokens": 200,
            "tools": [TOOL],
            "tool_choice": "auto",
            "response_format": {"type": "json_object"},
            "stop": ["END"],
            "seed": 7,
        }
        response = make_client(tmp_path).post("/v1/chat/completions", json=body, headers=HEADERS)
        assert response.status_code == 200
        assert upstream.payloads[0] == body

    def test_nothing_is_added_and_user_id_is_removed(self, tmp_path, upstream):
        chat(make_client(tmp_path), [USER], user_id="someone")
        assert upstream.payloads[0] == {"model": "gpt-6-sol", "messages": [USER]}

    def test_temperature_is_forwarded_only_when_sent(self, tmp_path, upstream):
        client = make_client(tmp_path)
        chat(client, [USER], temperature=0.2)
        assert upstream.payloads[0]["temperature"] == 0.2
        assert chat(client, [USER], temperature=5).status_code == 422

    def test_list_style_text_content_is_accepted(self, tmp_path, upstream):
        message = {"role": "user", "content": [{"type": "text", "text": "Hello"}, {"type": "text", "text": "there"}]}
        assert chat(make_client(tmp_path), [message]).status_code == 200
        assert upstream.payloads[0]["messages"] == [message]

    def test_empty_assistant_content_is_accepted(self, tmp_path):
        assert chat(make_client(tmp_path), [USER, {"role": "assistant", "content": ""}, USER]).status_code == 200

    def test_invalid_role_is_still_rejected(self, tmp_path):
        assert chat(make_client(tmp_path), [{"role": "root", "content": "hi"}, USER]).status_code == 422

    def test_overlong_text_is_still_rejected(self, tmp_path):
        assert chat(make_client(tmp_path), [{"role": "user", "content": "x" * 128_001}]).status_code == 422


class TestEveryPartOfTheRequestIsScanned:
    @pytest.mark.parametrize(
        "extra_message_or_field",
        [
            {"messages": [{"role": "user", "content": [{"type": "text", "text": "My SSN is 123-45-6789"}]}]},
            {
                "messages": [
                    USER,
                    {
                        **TOOL_CALL,
                        "tool_calls": [
                            {
                                "id": "c1",
                                "type": "function",
                                "function": {"name": "lookup", "arguments": '{"ssn": "123-45-6789"}'},
                            }
                        ],
                    },
                ]
            },
            {"messages": [USER, TOOL_CALL, {"role": "tool", "tool_call_id": "call_A10", "content": "SSN 123-45-6789"}]},
            {
                "messages": [USER],
                "tools": [
                    {"type": "function", "function": {"name": "f", "description": "Use key AKIAIOSFODNN7EXAMPLE"}}
                ],
            },
            {"messages": [USER], "metadata": {"note": "SSN 123-45-6789"}},
            {"messages": [USER], "prediction": {"type": "content", "content": "SSN 123-45-6789"}},
            {
                "messages": [
                    USER,
                    {"role": "assistant", "content": "ok", "name": "bot", "audio": {"transcript": "SSN 123-45-6789"}},
                ]
            },
        ],
        ids=[
            "content part",
            "tool call arguments",
            "tool result",
            "tool description",
            "metadata",
            "prediction",
            "nested field",
        ],
    )
    def test_blocked_wherever_the_data_is(self, tmp_path, upstream, extra_message_or_field):
        client = make_client(tmp_path)
        response = client.post(
            "/v1/chat/completions", json={"model": "gpt-6-sol", **extra_message_or_field}, headers=HEADERS
        )
        assert response.status_code == 403
        assert upstream.payloads == []

    def test_redaction_reaches_parts_tool_results_and_other_fields(self, tmp_path, upstream):
        response = chat(
            make_client(tmp_path),
            [
                {"role": "user", "content": [{"type": "text", "text": "Mail alice@example.com"}]},
                TOOL_CALL,
                {"role": "tool", "tool_call_id": "call_A10", "content": "Sent to bob@example.com"},
            ],
            metadata={"owner": "carol@example.com"},
        )
        assert response.status_code == 200
        forwarded = json.dumps(upstream.payloads[0])
        assert "@example.com" not in forwarded
        assert forwarded.count("[EMAIL_REDACTED]") == 3

    def test_ids_the_api_matches_exactly_are_never_rewritten(self, tmp_path, upstream):
        """'A10' looks like a diagnosis code to the scanner. As an ID it must survive."""
        chat(make_client(tmp_path), [USER, TOOL_CALL, {"role": "tool", "tool_call_id": "call_A10", "content": "18C"}])
        sent = upstream.payloads[0]["messages"]
        assert sent[1]["tool_calls"][0]["id"] == "call_A10"
        assert sent[2]["tool_call_id"] == "call_A10"

    def test_monitoring_mode_forwards_the_original(self, tmp_path, upstream):
        message = {"role": "user", "content": [{"type": "text", "text": "Mail alice@example.com"}]}
        chat(make_client(tmp_path, enforcement_mode="monitoring"), [message])
        assert upstream.payloads[0]["messages"] == [message]
        assert audit_entries(tmp_path)[0]["status"] == "REDACTED"


IMAGE = {
    "role": "user",
    "content": [
        {"type": "text", "text": "What is this?"},
        {"type": "image_url", "image_url": {"url": "data:image/png;base64,AKIAIOSFODNN7EXAMPLE"}},
    ],
}


class TestContentThatCannotBeScanned:
    def test_images_are_refused_by_default(self, tmp_path, upstream):
        response = chat(make_client(tmp_path), [IMAGE])
        assert response.status_code == 403
        assert upstream.payloads == []
        entry = audit_entries(tmp_path)[0]
        assert entry["status"] == "BLOCKED" and entry["details"] == ["UNSCANNABLE_CONTENT_IMAGE_URL"]

    @pytest.mark.parametrize(
        "part",
        [
            {"type": "input_audio", "input_audio": {"data": "AAAA", "format": "wav"}},
            {"type": "file", "file": {"file_id": "file-1"}},
            {"type": "something_new", "payload": "x"},
            {"payload": "no type at all"},
        ],
    )
    def test_audio_files_and_unknown_parts_are_refused_by_default(self, tmp_path, part):
        assert chat(make_client(tmp_path), [{"role": "user", "content": [part]}]).status_code == 403

    def test_policy_can_allow_them_and_they_pass_through_untouched(self, tmp_path, upstream):
        client = make_client(tmp_path, policy_path=permissive_policy(tmp_path))
        assert chat(client, [IMAGE]).status_code == 200
        assert upstream.payloads[0]["messages"] == [IMAGE]

    def test_text_beside_an_allowed_image_is_still_scanned(self, tmp_path, upstream):
        client = make_client(tmp_path, policy_path=permissive_policy(tmp_path))
        message = {"role": "user", "content": [{"type": "text", "text": "SSN 123-45-6789"}, IMAGE["content"][1]]}
        assert chat(client, [message]).status_code == 403

    def test_monitoring_mode_logs_and_forwards(self, tmp_path, upstream):
        assert chat(make_client(tmp_path, enforcement_mode="monitoring"), [IMAGE]).status_code == 200
        assert audit_entries(tmp_path)[0]["details"] == ["UNSCANNABLE_CONTENT_IMAGE_URL"]

    def test_policy_setting_must_be_true_or_false(self, tmp_path):
        path = tmp_path / "policy.yaml"
        path.write_text("global_settings:\n  allow_non_text_content: sometimes\n")
        with pytest.raises(PolicyError, match="allow_non_text_content must be true or false"):
            load_policy(path, strict=True)


class TestStreaming:
    def test_streaming_is_refused_with_a_clear_message(self, tmp_path, upstream):
        response = chat(make_client(tmp_path), [USER], stream=True)
        assert response.status_code == 400
        assert "Streaming is not supported" in response.json()["detail"]
        assert upstream.payloads == []

    def test_stream_false_is_fine(self, tmp_path):
        assert chat(make_client(tmp_path), [USER], stream=False).status_code == 200


class TestResponses:
    def respond(self, upstream, monkeypatch, response_body):
        async def reply(url, api_key, request_payload, timeout=60.0):
            return response_body

        from ai_governance import server

        monkeypatch.setattr(server, "call_upstream_llm", reply)

    def test_tool_call_reply_with_no_text_is_returned(self, tmp_path, upstream, monkeypatch):
        body = {
            "id": "chatcmpl-1",
            "model": "gpt-6-sol",
            "choices": [{"index": 0, "finish_reason": "tool_calls", "message": TOOL_CALL}],
        }
        self.respond(upstream, monkeypatch, body)
        response = chat(make_client(tmp_path), [USER], tools=[TOOL])
        assert response.status_code == 200 and response.json() == body

    @pytest.mark.parametrize(
        "leaky_message",
        [
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "c1",
                        "type": "function",
                        "function": {"name": "save", "arguments": '{"note": "SSN 123-45-6789"}'},
                    }
                ],
            },
            {"role": "assistant", "content": None, "refusal": "I can't share the SSN 123-45-6789."},
            {"role": "assistant", "content": [{"type": "text", "text": "SSN 123-45-6789"}]},
        ],
        ids=["tool call arguments", "refusal", "content parts"],
    )
    def test_leak_anywhere_in_the_reply_is_suppressed(self, tmp_path, upstream, monkeypatch, leaky_message):
        self.respond(upstream, monkeypatch, {"choices": [{"index": 0, "message": leaky_message}]})
        response = chat(make_client(tmp_path), [USER])
        assert response.status_code == 502 and "123-45-6789" not in response.text

    def test_leak_in_a_later_choice_is_suppressed(self, tmp_path, upstream, monkeypatch):
        choices = [
            {"index": 0, "message": {"role": "assistant", "content": "fine"}},
            {"index": 1, "message": {"role": "assistant", "content": "SSN 123-45-6789"}},
        ]
        self.respond(upstream, monkeypatch, {"choices": choices})
        assert chat(make_client(tmp_path), [USER], n=2).status_code == 502

    def test_unexpected_reply_shape_does_not_crash(self, tmp_path, upstream, monkeypatch):
        self.respond(upstream, monkeypatch, {"unexpected": True})
        response = chat(make_client(tmp_path), [USER])
        assert response.status_code == 200 and response.json() == {"unexpected": True}


class TestPayloadScanner:
    def test_original_request_is_not_modified(self):
        scanner = InputScanner(load_policy(POLICY, strict=True))
        original = {"model": "gpt-6-sol", "messages": [{"role": "user", "content": "Mail alice@example.com"}]}
        result = scan_request_payload(original, scanner)
        assert result.status == "REDACTED"
        assert original["messages"][0]["content"] == "Mail alice@example.com"
        assert result.payload["messages"][0]["content"] == "Mail [EMAIL_REDACTED]"

    def test_model_name_is_not_scanned(self):
        scanner = InputScanner(load_policy(POLICY, strict=True))
        result = scan_request_payload({"model": "AKIAIOSFODNN7EXAMPLE", "messages": [USER]}, scanner)
        assert result.status == "CLEAN"
