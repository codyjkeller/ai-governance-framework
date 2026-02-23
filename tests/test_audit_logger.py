"""Tests for the audit logger.

Verifies JSONL output, hash chain integrity, and tamper detection.
"""

import json

from ai_governance.audit.logger import AuditLogger


class TestAuditLogging:
    def test_creates_log_file(self, audit_logger):
        audit_logger.log_event("TEST", "tx-001", "SUCCESS", "test entry")
        assert audit_logger.log_path.exists()

    def test_writes_valid_jsonl(self, audit_logger):
        audit_logger.log_event("INPUT_SCAN", "tx-001", "BLOCKED", "SSN Detected", user_id="user1")
        with open(audit_logger.log_path) as f:
            entry = json.loads(f.readline())
        assert entry["event_type"] == "INPUT_SCAN"
        assert entry["transaction_id"] == "tx-001"
        assert entry["status"] == "BLOCKED"
        assert entry["user_id"] == "user1"
        assert "timestamp" in entry
        assert "prev_hash" in entry

    def test_includes_policy_version(self, audit_logger):
        audit_logger.log_event("TEST", "tx-001", "SUCCESS", "test", policy_version="3.0")
        with open(audit_logger.log_path) as f:
            entry = json.loads(f.readline())
        assert entry["policy_version"] == "3.0"


class TestHashChainIntegrity:
    def test_first_entry_uses_genesis_hash(self, audit_logger):
        audit_logger.log_event("TEST", "tx-001", "SUCCESS", "first")
        with open(audit_logger.log_path) as f:
            entry = json.loads(f.readline())
        assert entry["prev_hash"] == AuditLogger.GENESIS_HASH

    def test_chain_verifies_clean(self, audit_logger):
        audit_logger.log_event("TEST", "tx-001", "SUCCESS", "first")
        audit_logger.log_event("TEST", "tx-002", "BLOCKED", "second")
        audit_logger.log_event("TEST", "tx-003", "SUCCESS", "third")
        is_valid, count = audit_logger.verify_chain()
        assert is_valid is True
        assert count == 3

    def test_detects_tampered_entry(self, audit_logger):
        audit_logger.log_event("TEST", "tx-001", "SUCCESS", "first")
        audit_logger.log_event("TEST", "tx-002", "BLOCKED", "second")

        # Tamper with the first entry
        lines = audit_logger.log_path.read_text().splitlines()
        entry = json.loads(lines[0])
        entry["status"] = "TAMPERED"
        lines[0] = json.dumps(entry, separators=(",", ":"))
        audit_logger.log_path.write_text("\n".join(lines) + "\n")

        # Verification should fail
        new_logger = AuditLogger(audit_logger.log_path)
        is_valid, _ = new_logger.verify_chain()
        assert is_valid is False

    def test_survives_restart(self, tmp_path):
        """Chain should continue correctly after creating a new AuditLogger instance."""
        log_path = tmp_path / "restart_test.jsonl"

        # First session
        logger1 = AuditLogger(log_path)
        logger1.log_event("TEST", "tx-001", "SUCCESS", "session 1")

        # Second session (simulates restart)
        logger2 = AuditLogger(log_path)
        logger2.log_event("TEST", "tx-002", "SUCCESS", "session 2")

        # Chain should still be valid
        verifier = AuditLogger(log_path)
        is_valid, count = verifier.verify_chain()
        assert is_valid is True
        assert count == 2

    def test_empty_log_verifies(self, tmp_path):
        logger = AuditLogger(tmp_path / "empty.jsonl")
        is_valid, count = logger.verify_chain()
        assert is_valid is True
        assert count == 0
