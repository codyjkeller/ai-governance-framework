"""Tests for audit log signing and off-machine anchoring.

The attacker in these tests can read and write every file in the audit
directory but does not have the signing key.
"""

import hashlib
import json
import shutil
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ai_governance.audit.anchor import AnchorPublisher
from ai_governance.audit.logger import AuditLogger, AuditWriteError
from ai_governance.config import Settings
from ai_governance.server import ConfigurationError, create_app

KEY = "test-signing-key-not-a-real-secret-000000"
POLICY = Path(__file__).parent.parent / "policies" / "generative_ai_aup.yaml"
HEADERS = {"X-Governance-API-Key": "k1"}


def signed_log(tmp_path, entries=5, **kwargs):
    logger = AuditLogger(tmp_path / "audit.jsonl", hmac_key=KEY, **kwargs)
    for i in range(entries):
        logger.log_event("TEST", f"tx-{i}", "SUCCESS", "entry")
    return logger


def reopen(logger):
    """A fresh process: nothing remembered from before."""
    return AuditLogger(logger.log_path, hmac_key=KEY)


def sha(line):
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


def forge_chain(lines):
    """What an attacker without the key can do: recompute every plain hash."""
    forged, prev = [], "0" * 64
    for line in lines:
        entry = json.loads(line)
        entry["prev_hash"] = prev
        text = json.dumps(entry, separators=(",", ":"))
        forged.append(text)
        prev = sha(text)
    return forged, prev


class TestSignedLog:
    def test_entries_and_head_record_are_signed(self, tmp_path):
        logger = signed_log(tmp_path)
        entries = [json.loads(line) for line in logger.log_path.read_text().splitlines()]
        assert all(len(e["mac"]) == 64 for e in entries)
        assert len(json.loads(logger.head_path.read_text())["mac"]) == 64
        assert reopen(logger).verify_chain() == (True, 5)

    def test_the_key_never_appears_in_the_files(self, tmp_path):
        logger = signed_log(tmp_path)
        assert KEY not in logger.log_path.read_text() + logger.head_path.read_text()

    def test_a_different_key_does_not_verify(self, tmp_path):
        logger = signed_log(tmp_path)
        other = AuditLogger(logger.log_path, hmac_key="another-key-that-is-long-enough-0000000")
        assert other.verify_chain()[0] is False


class TestAttackerWithoutTheKey:
    def test_rewriting_an_entry_and_every_hash_is_detected(self, tmp_path):
        logger = signed_log(tmp_path)
        lines = logger.log_path.read_text().splitlines()
        entry = json.loads(lines[1])
        entry["status"] = "ALTERED"
        lines[1] = json.dumps(entry, separators=(",", ":"))
        forged, last_hash = forge_chain(lines)
        logger.log_path.write_text("\n".join(forged) + "\n")
        logger.head_path.write_text(json.dumps({"entries": 5, "last_hash": last_hash}))
        assert reopen(logger).verify_chain()[0] is False

    def test_deleting_entries_and_rewriting_the_head_record_is_detected(self, tmp_path):
        """The gap this closes: with plain hashes, this deletion verified as valid."""
        logger = signed_log(tmp_path)
        kept = logger.log_path.read_text().splitlines()[:3]
        logger.log_path.write_text("\n".join(kept) + "\n")
        logger.head_path.write_text(json.dumps({"entries": 3, "last_hash": sha(kept[-1])}))

        assert reopen(logger).verify_chain()[0] is False
        with pytest.raises(AuditWriteError):
            reopen(logger).log_event("TEST", "tx-new", "SUCCESS", "entry")

    def test_the_same_deletion_goes_unnoticed_without_signing(self, tmp_path):
        """Shows why the key matters: this is the attack against an unsigned log."""
        logger = AuditLogger(tmp_path / "audit.jsonl")
        for i in range(5):
            logger.log_event("TEST", f"tx-{i}", "SUCCESS", "entry")
        kept = logger.log_path.read_text().splitlines()[:3]
        logger.log_path.write_text("\n".join(kept) + "\n")
        logger.head_path.write_text(json.dumps({"entries": 3, "last_hash": sha(kept[-1])}))
        assert AuditLogger(logger.log_path).verify_chain() == (True, 3)

    def test_removing_the_head_record_is_detected(self, tmp_path):
        logger = signed_log(tmp_path)
        logger.head_path.unlink()
        assert reopen(logger).verify_chain()[0] is False
        with pytest.raises(AuditWriteError):
            reopen(logger).log_event("TEST", "tx-new", "SUCCESS", "entry")

    def test_stripping_signatures_is_detected(self, tmp_path):
        logger = signed_log(tmp_path)
        lines = []
        for line in logger.log_path.read_text().splitlines():
            entry = json.loads(line)
            del entry["mac"]
            lines.append(json.dumps(entry, separators=(",", ":")))
        forged, last_hash = forge_chain(lines)
        logger.log_path.write_text("\n".join(forged) + "\n")
        logger.head_path.write_text(json.dumps({"entries": 5, "last_hash": last_hash}))
        assert reopen(logger).verify_chain()[0] is False

    def test_appending_an_unsigned_entry_is_detected(self, tmp_path):
        logger = signed_log(tmp_path)
        lines = logger.log_path.read_text().splitlines()
        fake = json.dumps({"event_type": "FAKE", "prev_hash": sha(lines[-1])}, separators=(",", ":"))
        logger.log_path.write_text("\n".join([*lines, fake]) + "\n")
        assert reopen(logger).verify_chain()[0] is False


class TestRestoringAnOlderCopy:
    """An older log and head record are both validly signed. Only a copy of
    the head record held elsewhere can show that newer entries are gone."""

    @pytest.fixture
    def rolled_back(self, tmp_path):
        anchors = []
        logger = signed_log(tmp_path, entries=3, on_head=anchors.append)
        backup = tmp_path / "backup"
        backup.mkdir()
        shutil.copy(logger.log_path, backup / "log")
        shutil.copy(logger.head_path, backup / "head")
        for i in range(3, 6):
            logger.log_event("TEST", f"tx-{i}", "SUCCESS", "entry")
        shutil.copy(backup / "log", logger.log_path)
        shutil.copy(backup / "head", logger.head_path)
        return logger, anchors

    def test_the_running_process_refuses_to_write(self, rolled_back):
        logger, _ = rolled_back
        with pytest.raises(AuditWriteError):
            logger.log_event("TEST", "tx-after", "SUCCESS", "entry")

    def test_a_stored_anchor_exposes_it_even_after_a_restart(self, rolled_back):
        logger, anchors = rolled_back
        fresh = reopen(logger)
        assert fresh.verify_chain() == (True, 3)  # locally it looks fine
        newest = anchors[-1]
        assert newest["entries"] == 6
        assert fresh.verify_anchor(newest["entries"], newest["last_hash"]) is False

    def test_anchors_from_before_the_cut_still_match(self, rolled_back):
        logger, anchors = rolled_back
        assert reopen(logger).verify_anchor(anchors[1]["entries"], anchors[1]["last_hash"]) is True

    def test_anchor_with_the_wrong_hash_does_not_match(self, rolled_back):
        logger, _ = rolled_back
        assert reopen(logger).verify_anchor(2, "f" * 64) is False
        assert reopen(logger).verify_anchor(0, "f" * 64) is False


class TestAnchorPublisher:
    def test_sends_the_newest_head_record(self):
        received, done = [], threading.Event()

        def send(payload):
            received.append(payload)
            done.set()

        publisher = AnchorPublisher("https://collector.example/anchor", send=send)
        publisher.submit({"entries": 7, "last_hash": "a" * 64, "mac": "b" * 64})
        assert done.wait(5)
        assert received[0]["entries"] == 7 and received[0]["type"] == "audit_head"
        assert _wait_for(lambda: publisher.status()["last_entries_anchored"] == 7)
        assert publisher.status()["consecutive_failures"] == 0

    def test_retries_after_a_failure_and_reports_it(self):
        attempts, done = [], threading.Event()

        def send(payload):
            attempts.append(payload)
            if len(attempts) == 1:
                raise ConnectionError("collector down")
            done.set()

        publisher = AnchorPublisher("https://collector.example/anchor", send=send, retry_seconds=0.05)
        publisher.submit({"entries": 3, "last_hash": "a" * 64})
        assert done.wait(5)
        assert len(attempts) == 2 and attempts[1]["entries"] == 3
        assert _wait_for(lambda: publisher.status()["last_success"] is not None)

    def test_logger_hands_every_head_record_to_the_publisher(self, tmp_path):
        heads = []
        signed_log(tmp_path, entries=3, on_head=heads.append)
        assert [h["entries"] for h in heads] == [1, 2, 3]
        assert all(len(h["mac"]) == 64 and h["timestamp"] for h in heads)


def _wait_for(condition, seconds=5.0):
    import time

    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.01)
    return False


class TestServer:
    def settings(self, tmp_path, **overrides):
        values = {
            "llm_api_key": "sk-test-not-a-real-key-for-unit-tests-only",
            "policy_path": POLICY,
            "audit_log_path": tmp_path / "audit.jsonl",
            "rate_limit": 0,
            "proxy_api_keys": ["app:k1"],
            "audit_hmac_key": KEY,
        }
        values.update(overrides)
        return Settings(**values)

    def test_refuses_to_start_without_a_signing_key(self, tmp_path):
        with pytest.raises(ConfigurationError, match="AUDIT_HMAC_KEY is not set"):
            create_app(settings=self.settings(tmp_path, audit_hmac_key=""))

    def test_short_signing_key_is_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="at least 32 characters"):
            self.settings(tmp_path, audit_hmac_key="too-short")

    def test_anchor_url_must_be_https(self, tmp_path):
        with pytest.raises(ValueError, match="https://"):
            self.settings(tmp_path, audit_anchor_url="http://collector.example/anchor")

    def test_health_reports_signing_and_anchoring(self, tmp_path):
        health = TestClient(create_app(settings=self.settings(tmp_path))).get("/health").json()
        assert health["audit_signing"] is True and health["audit_anchor"] == {"configured": False}

    def test_requests_produce_signed_entries_and_verify(self, tmp_path):
        client = TestClient(create_app(settings=self.settings(tmp_path)))
        body = {"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]}
        assert client.post("/v1/chat/completions", json=body, headers=HEADERS).status_code == 200
        entries = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
        assert all("mac" in e for e in entries)

        head = json.loads((tmp_path / "audit.jsonl.head").read_text())
        ok = client.get(
            "/admin/audit/verify",
            params={"anchor_entries": head["entries"], "anchor_hash": head["last_hash"]},
            headers=HEADERS,
        ).json()
        assert ok == {"chain_valid": True, "entries_verified": 2, "anchor_found": True}
        missing = client.get(
            "/admin/audit/verify", params={"anchor_entries": 9, "anchor_hash": "f" * 64}, headers=HEADERS
        ).json()
        assert missing["anchor_found"] is False

    def test_blocked_request_sends_the_jira_alert(self, tmp_path, monkeypatch):
        from ai_governance import server

        alerts = []

        async def record(webhook, transaction_id, user_id, violation):
            alerts.append((webhook, user_id, violation))

        monkeypatch.setattr(server, "notify_jira", record)
        client = TestClient(create_app(settings=self.settings(tmp_path, jira_webhook="https://jira.example/hook")))
        body = {"model": "gpt-4", "messages": [{"role": "user", "content": "My SSN is 123-45-6789"}]}
        response = client.post("/v1/chat/completions", json=body, headers=HEADERS)
        assert response.status_code == 403
        assert response.json() == {"detail": "Request blocked by AI Acceptable Use Policy."}
        assert alerts == [("https://jira.example/hook", "app", "SSN")]
