"""Regex pattern registry for PII, PHI, and secret detection.

Each pattern is documented with:
- What it detects
- Known false-positive risks
- Known false-negative risks (bypass vectors)

IMPORTANT: Regex-based detection is a first-pass filter, not a complete
DLP solution. It will miss encoded, obfuscated, or context-dependent
sensitive data. Plan to layer NER models (e.g., Microsoft Presidio,
spaCy, AWS Comprehend) on top of this for production deployments.
"""

import re
from typing import NamedTuple


class PatternDefinition(NamedTuple):
    """A compiled regex pattern with its metadata."""

    name: str
    regex: re.Pattern[str]
    description: str
    false_positive_notes: str


# All patterns are pre-compiled for performance.
# The dict key is the lowercase name that maps to the YAML policy data_rules.
INPUT_PATTERNS: dict[str, PatternDefinition] = {
    # --- General PII ---
    "ssn": PatternDefinition(
        name="SSN",
        regex=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        description="US Social Security Number (dashed format: 123-45-6789).",
        false_positive_notes="Low. Format is distinctive. Does NOT catch space-separated or undashed SSNs.",
    ),
    "email": PatternDefinition(
        name="EMAIL",
        regex=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        description="Email addresses.",
        false_positive_notes="Low for standard emails. May miss non-ASCII domains.",
    ),
    "phone_us": PatternDefinition(
        name="PHONE_US",
        regex=re.compile(r"\b(?:\+?1[-.]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        description="US phone numbers in common formats.",
        false_positive_notes="Moderate. Can match 10-digit numeric strings that are not phones.",
    ),
    "us_zip_code": PatternDefinition(
        name="US_ZIP_CODE",
        regex=re.compile(r"\b\d{5}(?:-\d{4})?\b"),
        description="US ZIP codes (5-digit and ZIP+4).",
        false_positive_notes=(
            "HIGH. Matches any 5-digit number. Use with ALLOW action unless combined with address context."
        ),
    ),
    # --- Financial ---
    "credit_card": PatternDefinition(
        name="CREDIT_CARD",
        regex=re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),
        description="Credit card numbers (16 digits, optional dashes/spaces).",
        false_positive_notes="Moderate. Matches any 16-digit grouped number. No Luhn check.",
    ),
    "vin_number": PatternDefinition(
        name="VIN_NUMBER",
        regex=re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"),
        description="Vehicle Identification Numbers (17 chars, no I/O/Q).",
        false_positive_notes="HIGH. Matches any 17-char uppercase alphanumeric string (tokens, hashes, etc.).",
    ),
    # --- Infrastructure & Secrets ---
    "ip_address": PatternDefinition(
        name="IP_ADDRESS",
        regex=re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
        description="IPv4 addresses with valid octet ranges (0-255).",
        false_positive_notes="Low. Validates octet ranges. May match version strings in rare cases.",
    ),
    "aws_access_key": PatternDefinition(
        name="AWS_ACCESS_KEY",
        regex=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        description="AWS Access Key IDs (starts with AKIA or ASIA, 20 chars total).",
        false_positive_notes="Very low. The AKIA/ASIA prefix is highly specific.",
    ),
    "private_key_block": PatternDefinition(
        name="PRIVATE_KEY_BLOCK",
        regex=re.compile(r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY-----"),
        description="PEM-encoded private key headers.",
        false_positive_notes="Very low. The header format is unique.",
    ),
    "api_key_generic": PatternDefinition(
        name="API_KEY_GENERIC",
        regex=re.compile(r"(?i)(?:api_key|access_token|secret)\s*[:=]\s*[a-zA-Z0-9_\-]{20,}"),
        description="Generic API keys/tokens in key=value format.",
        false_positive_notes="Moderate. May match config file examples or documentation snippets.",
    ),
    # --- Healthcare (HIPAA) ---
    "icd10_code": PatternDefinition(
        name="ICD10_CODE",
        regex=re.compile(r"\b[A-TV-Z]\d{2}(?:\.\d{1,4})?\b"),
        description="ICD-10 medical diagnosis codes (e.g., J01.90).",
        false_positive_notes=(
            "Moderate. Restricted first-letter range (A-T, V-Z) reduces false positives vs old pattern. "
            "U-codes are reserved by WHO. Still may match part numbers or identifiers."
        ),
    ),
    "dea_number": PatternDefinition(
        name="DEA_NUMBER",
        regex=re.compile(r"\b[ABCDEFGHJKLMNPRSTUXabcdefghjklmnprstux][A-Za-z9]\d{7}\b"),
        description="DEA registration numbers (prescriber license IDs).",
        false_positive_notes="Low. First character restricted to valid DEA prefixes.",
    ),
}

# Output-specific patterns (risks in LLM responses)
OUTPUT_PATTERNS: dict[str, PatternDefinition] = {
    "leaked_api_key": PatternDefinition(
        name="LEAKED_API_KEY",
        regex=re.compile(r"(?i)(?:api_key|access_token|secret)\s*[:=]\s*[a-zA-Z0-9_\-]{20,}"),
        description="API keys or tokens in the LLM response.",
        false_positive_notes="Moderate. Same as input pattern. May flag code examples.",
    ),
    "leaked_ssn": PatternDefinition(
        name="LEAKED_SSN",
        regex=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        description="SSN patterns in the LLM response.",
        false_positive_notes="Low.",
    ),
    "leaked_aws_key": PatternDefinition(
        name="LEAKED_AWS_KEY",
        regex=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        description="AWS access keys in the LLM response.",
        false_positive_notes="Very low.",
    ),
    "suspicious_url": PatternDefinition(
        name="SUSPICIOUS_URL",
        regex=re.compile(r"https?://(?:[a-zA-Z0-9-]+\.)+(?:test|example|invalid|localhost)\b"),
        description="Hallucinated or test URLs in the LLM response.",
        false_positive_notes="Low. Only flags known non-routable TLDs.",
    ),
}
