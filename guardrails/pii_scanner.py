import re
import logging

class PIIScanner:
    """
    Layer 1 (Input) & Layer 5 (Safety) Defense:
    Scans prompts and completion outputs for sensitive patterns before 
    allowing data to leave the trust boundary.
    """
    
    PATTERNS = {
        'SSN': r'\b\d{3}-\d{2}-\d{4}\b',
        'EMAIL': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'CREDIT_CARD': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
        'API_KEY': r'(?i)(api_key|access_token|secret)\s*[:=]\s*[a-zA-Z0-9_\-]{20,}'
    }

    def __init__(self, sensitivity_level='high'):
        self.sensitivity = sensitivity_level
        logging.basicConfig(level=logging.INFO)

    def scan_text(self, text_content):
        """
        Returns a list of detected PII types.
        If list is empty, traffic is safe.
        """
        detected_risks = []
        
        for pii_type, pattern in self.PATTERNS.items():
            if re.search(pattern, text_content):
                logging.warning(f"Governance Alert: {pii_type} detected in payload.")
                detected_risks.append(pii_type)
        
        return detected_risks

    def redact(self, text_content):
        """
        Simple redaction wrapper to replace PII with <REDACTED>.
        """
        clean_text = text_content
        for pii_type, pattern in self.PATTERNS.items():
            clean_text = re.sub(pattern, f"<{pii_type}_REDACTED>", clean_text)
        return clean_text
