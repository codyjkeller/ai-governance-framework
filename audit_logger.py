import json
import logging
import time
from datetime import datetime
from pathlib import Path

class AuditLogger:
    """
    Layer 6: Immutable Compliance Logging.
    Records every transaction for GRC reviews.
    """
    def __init__(self, log_file="audit_logs/governance.jsonl"):
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(exist_ok=True)
        
        # Setup Logger
        self.logger = logging.getLogger("governance_audit")
        self.logger.setLevel(logging.INFO)
        
        # File Handler (JSONL)
        handler = logging.FileHandler(self.log_file)
        handler.setFormatter(logging.Formatter('%(message)s'))
        self.logger.addHandler(handler)

    def log_event(self, event_type, prompt_id, status, details, user_id="unknown"):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type, # INPUT_SCAN or OUTPUT_SCAN
            "transaction_id": prompt_id,
            "user_id": user_id,
            "status": status, # BLOCKED, REDACTED, SAFE
            "policy_version": "2.1",
            "details": details # List of violations
        }
        self.logger.info(json.dumps(entry))

# Usage Example
# auditor = AuditLogger()
# auditor.log_event("INPUT_SCAN", "tx-123", "BLOCKED", ["SSN Detected"])
