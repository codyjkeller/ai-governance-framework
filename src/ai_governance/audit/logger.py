"""Audit logger with integrity verification.

Records every governance decision (BLOCK, REDACT, CLEAN) to a JSONL file.
Each log entry includes a SHA-256 hash of the previous entry, creating
a tamper-evident chain. If any entry is modified or deleted, the chain
breaks and verification will detect it.

This is NOT true immutability (that requires write-once storage like
S3 Object Lock). This is tamper-evidence — you can detect modification
after the fact. For production, ship these logs to a SIEM or write-once
store in addition to local file output.
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class AuditLogger:
    """Tamper-evident JSONL audit logger.

    Each entry includes a `prev_hash` field containing the SHA-256
    hash of the previous entry's JSON string. The first entry uses
    a well-known genesis hash.
    """

    GENESIS_HASH = "0" * 64  # SHA-256 of "nothing" — the start of the chain

    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._prev_hash = self._recover_chain_head()

    def _recover_chain_head(self) -> str:
        """Read the last entry's hash to continue the chain on restart.

        If the log file doesn't exist or is empty, start a new chain.
        """
        if not self.log_path.exists():
            return self.GENESIS_HASH

        try:
            last_line = ""
            with open(self.log_path) as f:
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        last_line = stripped
            if last_line:
                return self._hash_entry(last_line)
        except Exception:
            logger.warning("Could not recover audit chain head. Starting new chain.")

        return self.GENESIS_HASH

    def log_event(
        self,
        event_type: str,
        transaction_id: str,
        status: str,
        details: str | list[Any],
        user_id: str = "unknown",
        policy_version: str = "unknown",
    ) -> None:
        """Append a tamper-evident audit entry.

        Args:
            event_type: Category of event (INPUT_SCAN, OUTPUT_SCAN, TRANSACTION_COMPLETE).
            transaction_id: Unique ID for this request.
            status: Outcome (BLOCKED, REDACTED, CLEAN, SUCCESS).
            details: Human-readable description or list of violations.
            user_id: Identity of the requester.
            policy_version: Version string from the active policy.
        """
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "transaction_id": transaction_id,
            "user_id": user_id,
            "status": status,
            "policy_version": policy_version,
            "details": details,
            "prev_hash": self._prev_hash,
        }

        entry_json = json.dumps(entry, separators=(",", ":"))

        try:
            with open(self.log_path, "a") as f:
                f.write(entry_json + "\n")
        except OSError as e:
            logger.error("Failed to write audit log: %s", e)
            return

        self._prev_hash = self._hash_entry(entry_json)

    @staticmethod
    def _hash_entry(entry_json: str) -> str:
        """Compute SHA-256 hash of a JSON log entry string."""
        return hashlib.sha256(entry_json.encode("utf-8")).hexdigest()

    def verify_chain(self) -> tuple[bool, int]:
        """Verify the integrity of the entire audit log.

        Reads every entry and checks that each entry's prev_hash
        matches the hash of the preceding entry.

        Returns:
            Tuple of (is_valid, entries_checked).
            If is_valid is False, the chain was tampered with.
        """
        if not self.log_path.exists():
            return True, 0

        prev_hash = self.GENESIS_HASH
        count = 0

        with open(self.log_path) as f:
            for line_num, line in enumerate(f, start=1):
                stripped = line.strip()
                if not stripped:
                    continue

                try:
                    entry = json.loads(stripped)
                except json.JSONDecodeError:
                    logger.error("Audit chain broken: invalid JSON at line %d", line_num)
                    return False, count

                if entry.get("prev_hash") != prev_hash:
                    logger.error(
                        "Audit chain broken at line %d: expected prev_hash=%s, got=%s",
                        line_num,
                        prev_hash[:16] + "...",
                        str(entry.get("prev_hash", ""))[:16] + "...",
                    )
                    return False, count

                prev_hash = self._hash_entry(stripped)
                count += 1

        return True, count
