"""Tests for the safety behavior of the proxy.

Covers: refusing to start when misconfigured, scanning every message,
log-only monitoring mode, audit identity, and refusing requests that
cannot be audited.
"""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ai_governance.audit.logger import AuditLogger, AuditWriteError
from ai_governance.config import Settings
from ai_governance.policy.loader import PolicyError
from ai_governance.scanning.input_scanner import InputScanner
from ai_governance.server import ConfigurationError, create_app

POLICY = Path(__file__).parent.parent / "policies" / "generative_ai_aup.yaml"
HEADERS = {"X-Governance-API-Key": "key-for-billing"}
SIGNING_KEY = "test-signing-key-not-a-real-secret-000000"


def make_settings(tmp_path, **overrides):
    values = {
        "llm_api_key": "sk-test-not-a-real-key-for-unit-tests-only",
        "audit_hmac_key": SIGNING_KEY,
        "policy_path": POLICY,
        "audit_log_path": tmp_path / "audit.jsonl",
        "rate_limit": 0,
        "proxy_api_keys": ["billing-app:key-for-billing", "bare-key-with-no-name"],
    }
    values.update(overrides)
    return Settings(**values)


def make_client(tmp_path, **overrides):
    return TestClient(create_app(settings=make_settings(tmp_path, **overrides)))


def chat(client, messages, headers=HEADERS, **extra):
    return client.post("/v1/chat/completions", json={"model": "gpt-4", "messages": messages, **extra}, headers=headers)


def audit_entries(tmp_path):
    return [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]


class TestStartupChecks:
    def test_refuses_to_start_without_api_keys(self, tmp_path):
        with pytest.raises(ConfigurationError, match="PROXY_API_KEYS is not set"):
            create_app(settings=make_settings(tmp_path, proxy_api_keys=[]))

    def test_refuses_to_start_with_missing_policy(self, tmp_path):
        with pytest.raises(PolicyError, match="not found"):
            create_app(settings=make_settings(tmp_path, policy_path=tmp_path / "nope.yaml"))

    def test_refuses_to_start_with_invalid_policy(self, tmp_path):
        policy = tmp_path / "policy.yaml"
        policy.write_text("data_rules:\n  ssn: {action: BLOK, sensitivity: CRITICAL}\n")
        with pytest.raises(PolicyError, match="BLOK"):
            create_app(settings=make_settings(tmp_path, policy_path=policy))

    def test_dev_flag_allows_both_and_is_reported(self, tmp_path):
        client = make_client(tmp_path, proxy_api_keys=[], policy_path=tmp_path / "nope.yaml", allow_insecure_dev=True)
        assert client.get("/health").json()["insecure_dev_mode"] is True
        assert chat(client, [{"role": "user", "content": "hello"}], headers={}).status_code == 200
        assert audit_entries(tmp_path)[0]["user_id"] == "unauthenticated"

    def test_normal_start_reports_dev_mode_off(self, tmp_path):
        assert make_client(tmp_path).get("/health").json()["insecure_dev_mode"] is False

    def test_importing_the_server_module_needs_no_configuration(self, monkeypatch):
        import importlib

        import ai_governance.server as server_module

        monkeypatch.delenv("LLM_API_KEY", raising=False)
        importlib.reload(server_module)  # would raise if the app were built at import time

    def test_keys_are_read_from_a_comma_separated_env_var(self, monkeypatch):
        monkeypatch.setenv("LLM_API_KEY", "sk-test-not-a-real-key-for-unit-tests-only")
        monkeypatch.setenv("PROXY_API_KEYS", "billing-app:abc123, plainkey")
        settings = Settings()
        assert settings.proxy_api_keys == ["billing-app:abc123", "plainkey"]
        identities = settings.api_key_identities()
        assert identities["abc123"] == "billing-app"
        assert identities["plainkey"].startswith("key-") and "plainkey" not in identities["plainkey"]


class TestEveryMessageIsScanned:
    def test_blocks_sensitive_data_in_an_earlier_message(self, tmp_path, upstream):
        client = make_client(tmp_path)
        response = chat(
            client,
            [
                {"role": "user", "content": "My SSN is 123-45-6789"},
                {"role": "assistant", "content": "Noted."},
                {"role": "user", "content": "Summarize the above."},
            ],
        )
        assert response.status_code == 403
        assert upstream.payloads == []

    def test_blocks_sensitive_data_in_the_system_prompt(self, tmp_path, upstream):
        client = make_client(tmp_path)
        response = chat(
            client,
            [{"role": "system", "content": "Use key AKIAIOSFODNN7EXAMPLE"}, {"role": "user", "content": "hello"}],
        )
        assert response.status_code == 403
        assert upstream.payloads == []

    def test_redacts_every_message_before_forwarding(self, tmp_path, upstream):
        client = make_client(tmp_path)
        response = chat(
            client,
            [
                {"role": "user", "content": "Write to alice@example.com"},
                {"role": "assistant", "content": "Done."},
                {"role": "user", "content": "And to bob@example.com"},
            ],
        )
        assert response.status_code == 200
        forwarded = json.dumps(upstream.payloads[0])
        assert "alice@example.com" not in forwarded and "bob@example.com" not in forwarded
        assert forwarded.count("[EMAIL_REDACTED]") == 2
        assert audit_entries(tmp_path)[0]["status"] == "REDACTED"


class TestScannerActions:
    def test_unknown_action_blocks(self):
        scanner = InputScanner({"data_rules": {"ssn": {"action": "BLOK", "sensitivity": "CRITICAL"}}})
        result = scanner.scan("SSN 123-45-6789")
        assert result.status == "BLOCKED" and result.text is None

    def test_allow_only_match_is_clean_but_recorded(self, input_scanner):
        result = input_scanner.scan("Ship to ZIP 94105")
        assert result.status == "CLEAN" and result.text == "Ship to ZIP 94105"
        assert [v["type"] for v in result.violations] == ["US_ZIP_CODE"]


class TestMonitoringModeIsLogOnly:
    def test_blockable_prompt_is_forwarded_unchanged_and_logged(self, tmp_path, upstream):
        client = make_client(tmp_path, enforcement_mode="monitoring")
        response = chat(client, [{"role": "user", "content": "My SSN is 123-45-6789"}])
        assert response.status_code == 200
        assert upstream.payloads[0]["messages"][0]["content"] == "My SSN is 123-45-6789"
        scan = audit_entries(tmp_path)[0]
        assert (scan["event_type"], scan["status"], scan["enforced"]) == ("INPUT_SCAN", "BLOCKED", False)

    def test_redactable_prompt_is_not_rewritten(self, tmp_path, upstream):
        client = make_client(tmp_path, enforcement_mode="monitoring")
        chat(client, [{"role": "user", "content": "Write to alice@example.com"}])
        assert upstream.payloads[0]["messages"][0]["content"] == "Write to alice@example.com"
        assert audit_entries(tmp_path)[0]["status"] == "REDACTED"

    def test_leaking_response_is_returned_unchanged_and_logged(self, tmp_path, upstream):
        upstream.reply = "The SSN on file is 123-45-6789."
        client = make_client(tmp_path, enforcement_mode="monitoring")
        response = chat(client, [{"role": "user", "content": "hello"}])
        assert response.json()["choices"][0]["message"]["content"] == "The SSN on file is 123-45-6789."
        events = {(e["event_type"], e["status"]) for e in audit_entries(tmp_path)}
        assert ("OUTPUT_SCAN", "BLOCKED") in events

    def test_disallowed_model_is_allowed_through_and_logged(self, tmp_path):
        client = make_client(tmp_path, enforcement_mode="monitoring")
        response = client.post(
            "/v1/chat/completions",
            json={"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "hello"}]},
            headers=HEADERS,
        )
        assert response.status_code == 200
        assert audit_entries(tmp_path)[0]["event_type"] == "MODEL_DENIED"


class TestBlockingMode:
    def test_leaking_response_is_suppressed(self, tmp_path, upstream):
        upstream.reply = "The SSN on file is 123-45-6789."
        response = chat(make_client(tmp_path), [{"role": "user", "content": "hello"}])
        assert response.status_code == 502
        assert "123-45-6789" not in response.text
        assert all(e["enforced"] is True for e in audit_entries(tmp_path))


class TestAuditIdentity:
    def test_audit_records_the_key_owner_not_the_claimed_user(self, tmp_path):
        chat(make_client(tmp_path), [{"role": "user", "content": "hello"}], user_id="ceo@example.com")
        for entry in audit_entries(tmp_path):
            assert entry["user_id"] == "billing-app"
            assert entry["client_user_id"] == "ceo@example.com"

    def test_bare_key_is_recorded_by_hash_not_value(self, tmp_path):
        chat(
            make_client(tmp_path),
            [{"role": "user", "content": "hello"}],
            headers={"X-Governance-API-Key": "bare-key-with-no-name"},
        )
        entry = audit_entries(tmp_path)[0]
        assert entry["user_id"].startswith("key-") and "bare-key" not in json.dumps(entry)
        assert "client_user_id" not in entry

    def test_the_name_part_alone_is_not_a_valid_key(self, tmp_path):
        client = make_client(tmp_path)
        for bad_key in ("billing-app", "billing-app:key-for-billing", "key-for-billin", ""):
            response = chat(client, [{"role": "user", "content": "hi"}], headers={"X-Governance-API-Key": bad_key})
            assert response.status_code == 401

    def test_verify_endpoint_requires_a_key(self, tmp_path):
        client = make_client(tmp_path)
        assert client.get("/admin/audit/verify").status_code == 401
        chat(client, [{"role": "user", "content": "hello"}])
        assert client.get("/admin/audit/verify", headers=HEADERS).json() == {"chain_valid": True, "entries_verified": 2}


class TestRateLimit:
    def test_limit_is_counted_per_api_key(self, tmp_path):
        client = make_client(tmp_path, rate_limit=2)
        message = [{"role": "user", "content": "hello"}]
        other = {"X-Governance-API-Key": "bare-key-with-no-name"}
        assert [chat(client, message).status_code for _ in range(3)] == [200, 200, 429]
        assert chat(client, message, headers=other).status_code == 200


class TestAuditFailureRefusesTheRequest:
    def test_unwritable_audit_log_returns_503_and_nothing_is_forwarded(self, tmp_path, upstream, monkeypatch):
        client = make_client(tmp_path)

        def fail(*args, **kwargs):
            raise AuditWriteError("disk full")

        monkeypatch.setattr(client.app.state.auditor, "log_event", fail)
        response = chat(client, [{"role": "user", "content": "hello"}])
        assert response.status_code == 503
        assert "audit log is unavailable" in response.json()["detail"]
        assert upstream.payloads == []

    def test_log_event_raises_when_the_file_cannot_be_written(self, tmp_path):
        logger = AuditLogger(tmp_path / "audit.jsonl")
        (tmp_path / "audit.jsonl").mkdir()  # a directory where the file should be
        with pytest.raises(AuditWriteError):
            logger.log_event("TEST", "tx-001", "SUCCESS", "entry")


class TestAuditChainWithSeveralWriters:
    def test_two_workers_sharing_one_file_keep_a_valid_chain(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        worker_a, worker_b = AuditLogger(path), AuditLogger(path)
        for i in range(5):
            worker_a.log_event("TEST", f"a-{i}", "SUCCESS", "entry")
            worker_b.log_event("TEST", f"b-{i}", "SUCCESS", "entry")
        assert AuditLogger(path).verify_chain() == (True, 10)

    def test_separate_processes_keep_a_valid_chain(self, tmp_path):
        import multiprocessing

        path = tmp_path / "audit.jsonl"
        context = multiprocessing.get_context("spawn")
        workers = [context.Process(target=_write_entries, args=(str(path), n)) for n in range(4)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=60)
            assert worker.exitcode == 0
        assert AuditLogger(path).verify_chain() == (True, 100)


def _write_entries(path, worker_number):
    logger = AuditLogger(Path(path))
    for i in range(25):
        logger.log_event("TEST", f"w{worker_number}-{i}", "SUCCESS", "entry")


class TestDeletedEntriesAreDetected:
    @pytest.fixture
    def log_with_five(self, tmp_path):
        logger = AuditLogger(tmp_path / "audit.jsonl")
        for i in range(5):
            logger.log_event("TEST", f"tx-{i}", "SUCCESS", "entry")
        return logger

    def test_deleting_the_newest_entries_fails_verification(self, log_with_five):
        lines = log_with_five.log_path.read_text().splitlines()
        log_with_five.log_path.write_text("\n".join(lines[:3]) + "\n")
        assert AuditLogger(log_with_five.log_path).verify_chain() == (False, 3)

    def test_writing_after_a_deletion_is_refused(self, log_with_five):
        lines = log_with_five.log_path.read_text().splitlines()
        log_with_five.log_path.write_text("\n".join(lines[:3]) + "\n")
        with pytest.raises(AuditWriteError):
            AuditLogger(log_with_five.log_path).log_event("TEST", "tx-new", "SUCCESS", "entry")

    def test_removing_the_head_record_fails_verification(self, log_with_five):
        log_with_five.head_path.unlink()
        assert AuditLogger(log_with_five.log_path).verify_chain() == (False, 5)

    def test_deleting_the_whole_log_fails_verification(self, log_with_five):
        log_with_five.log_path.unlink()
        assert AuditLogger(log_with_five.log_path).verify_chain() == (False, 0)

    def test_crash_between_entry_and_head_update_recovers(self, log_with_five):
        # Simulate: the 5th entry reached the file but the head record still describes 4.
        lines = log_with_five.log_path.read_text().splitlines()
        fourth_hash = AuditLogger._hash_entry(lines[3])
        log_with_five.head_path.write_text(json.dumps({"entries": 4, "last_hash": fourth_hash}))
        restarted = AuditLogger(log_with_five.log_path)
        restarted.log_event("TEST", "tx-after-crash", "SUCCESS", "entry")
        assert restarted.verify_chain() == (True, 6)

    def test_log_from_an_older_version_is_adopted_on_first_write(self, tmp_path):
        logger = AuditLogger(tmp_path / "audit.jsonl")
        logger.log_event("TEST", "tx-0", "SUCCESS", "entry")
        logger.head_path.unlink()  # logs written before head records existed have none
        upgraded = AuditLogger(tmp_path / "audit.jsonl")
        upgraded.log_event("TEST", "tx-1", "SUCCESS", "entry")
        assert upgraded.verify_chain() == (True, 2)
