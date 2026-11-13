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
from collections.abc import Callable
from typing import NamedTuple


class PatternDefinition(NamedTuple):
    """A compiled regex pattern with its metadata.

    Some identifiers look like ordinary text or numbers, so two optional
    extras keep false alarms down:

    - A group named `value` (or `value2`, ... for alternatives) in the regex. The pattern can then require a
      label next to the identifier ("MRN: 00123456") while only the
      identifier itself is reported and redacted.
    - A `validator` that checks a candidate after the regex matches, for
      identifiers with a built-in check digit (card and DEA numbers).
    """

    name: str
    regex: re.Pattern[str]
    description: str
    false_positive_notes: str
    validator: Callable[[str], bool] | None = None


def find_matches(pattern: PatternDefinition, text: str) -> list[str]:
    """Return the distinct values in text that match a pattern and pass its validator."""
    found: list[str] = []
    for match in pattern.regex.finditer(text):
        # A pattern with alternatives may name its groups value, value2, ...
        named = [v for k, v in match.groupdict().items() if k.startswith("value")]
        value = next((v for v in named if v), None) if named else match.group(0)
        if not value or value in found:
            continue
        if pattern.validator is not None and not pattern.validator(value):
            continue
        found.append(value)
    return found


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def passes_luhn(value: str) -> bool:
    """The check-digit test every payment card number satisfies.

    About nine in ten random 16-digit numbers fail it, which is what stops
    order numbers and tracking IDs from being treated as cards.
    """
    digits = [int(d) for d in _digits(value)]
    if len(digits) < 13:
        return False
    total = 0
    for position, digit in enumerate(reversed(digits)):
        if position % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def passes_dea_checksum(value: str) -> bool:
    """A DEA number's last digit is a checksum of the six digits before it."""
    digits = [int(d) for d in value[2:]]
    if len(digits) != 7:
        return False
    total = digits[0] + digits[2] + digits[4] + 2 * (digits[1] + digits[3] + digits[5])
    return total % 10 == digits[6]


# All patterns are pre-compiled for performance.
# The dict key is the lowercase name that maps to the YAML policy data_rules.
INPUT_PATTERNS: dict[str, PatternDefinition] = {
    # --- General PII ---
    "ssn": PatternDefinition(
        name="SSN",
        regex=re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        description="US Social Security Number (dashed format: 123-45-6789).",
        false_positive_notes=(
            "Low. Format is distinctive, and number ranges the SSA never issues (000, 666, 9xx) are skipped. "
            "Undashed and spaced SSNs are covered by ssn_unformatted."
        ),
    ),
    "ssn_unformatted": PatternDefinition(
        name="SSN_UNFORMATTED",
        regex=re.compile(
            r"(?i)\b(?:ssn|social\s+security(?:\s+(?:number|no\.?|#))?)\D{0,10}"
            r"(?P<value>(?!000|666|9\d\d)\d{3} ?(?!00)\d{2} ?(?!0000)\d{4})\b"
        ),
        description="SSN written without dashes (123456789 or 123 45 6789), when labelled as an SSN.",
        false_positive_notes=(
            "Low. Nine digits alone are far too common, so a label such as 'SSN' or 'Social Security' "
            "must come just before the number. An unlabelled undashed SSN is not caught."
        ),
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
        regex=re.compile(r"\b(?:\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}|3[47]\d{2}[- ]?\d{6}[- ]?\d{5})\b"),
        description="Payment card numbers: 16 digits, or 15-digit American Express, optional dashes/spaces.",
        false_positive_notes=(
            "Low. Candidates must pass the Luhn check digit test, which rejects about 90% of "
            "ordinary 16-digit numbers such as order or tracking IDs."
        ),
        validator=passes_luhn,
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
        regex=re.compile(r"-----BEGIN\s+(?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED|PGP)\s+)?PRIVATE\s+KEY(?:\s+BLOCK)?-----"),
        description="PEM-encoded private key headers, including the plain 'BEGIN PRIVATE KEY' (PKCS#8) form.",
        false_positive_notes="Very low. The header format is unique.",
    ),
    "github_token": PatternDefinition(
        name="GITHUB_TOKEN",
        regex=re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
        description="GitHub personal access, OAuth, app and fine-grained tokens.",
        false_positive_notes="Very low. The prefixes are specific to GitHub.",
    ),
    "llm_api_key": PatternDefinition(
        name="LLM_API_KEY",
        regex=re.compile(r"\bsk-(?:[A-Za-z]+-)*[A-Za-z0-9_-]{20,}"),
        description="OpenAI- and Anthropic-style API keys (sk-..., sk-proj-..., sk-ant-...).",
        false_positive_notes="Low. Requires the sk- prefix followed by at least 20 key characters.",
    ),
    "slack_token": PatternDefinition(
        name="SLACK_TOKEN",
        regex=re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
        description="Slack bot, user and app tokens.",
        false_positive_notes="Very low. The xox prefix is specific to Slack.",
    ),
    "google_api_key": PatternDefinition(
        name="GOOGLE_API_KEY",
        regex=re.compile(r"\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])"),
        description="Google API keys.",
        false_positive_notes="Very low. Fixed prefix and length.",
    ),
    "stripe_key": PatternDefinition(
        name="STRIPE_KEY",
        regex=re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}"),
        description="Stripe live secret and restricted keys.",
        false_positive_notes="Very low. Test-mode keys (sk_test_) are not matched.",
    ),
    "jwt": PatternDefinition(
        name="JWT",
        regex=re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        description="JSON Web Tokens (three base64url parts, the first two starting with eyJ).",
        false_positive_notes="Very low. Matches expired and example tokens too.",
    ),
    "bearer_token": PatternDefinition(
        name="BEARER_TOKEN",
        regex=re.compile(r"(?i)\bBearer\s+(?P<value>[A-Za-z0-9_\-.=+/]{20,})"),
        description="Tokens in an 'Authorization: Bearer ...' header.",
        false_positive_notes="Low. Needs the word Bearer followed by 20 or more token characters.",
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
        regex=re.compile(
            r"(?i:\b(?:icd(?:-?10)?|diagnos[ie]s|dx|code)\b)\W{0,15}(?P<value>[A-TV-Z]\d{2}(?:\.\d{1,4})?)\b"
            r"|\b(?P<value2>[A-TV-Z]\d{2}\.\d{1,4})\b"
        ),
        description="ICD-10 medical diagnosis codes (e.g., J01.90).",
        false_positive_notes=(
            "Low to moderate. A code with a decimal part (J01.90) is matched anywhere. A bare three-character "
            "code (J01) is matched only after a word such as 'ICD', 'diagnosis', 'dx' or 'code', because "
            "'vitamin B12' and 'room A10' have the same shape."
        ),
    ),
    "dea_number": PatternDefinition(
        name="DEA_NUMBER",
        regex=re.compile(r"\b[ABCDEFGHJKLMNPRSTUXabcdefghjklmnprstux][A-Za-z9]\d{7}\b"),
        description="DEA registration numbers (prescriber license IDs).",
        false_positive_notes=(
            "Very low. First character restricted to valid DEA prefixes, and the check digit must be correct."
        ),
        validator=passes_dea_checksum,
    ),
    "medical_record_number": PatternDefinition(
        name="MEDICAL_RECORD_NUMBER",
        regex=re.compile(
            r"(?i)\b(?:mrn|medical\s+record\s+(?:number|no\.?|#))\W{0,5}(?P<value>(?=[A-Z0-9-]*\d)[A-Z0-9-]{5,15})\b"
        ),
        description="Medical record numbers, when labelled 'MRN' or 'medical record number'.",
        false_positive_notes=(
            "Low. Needs the label, and the value must contain a digit. Unlabelled MRNs are not caught."
        ),
    ),
    "date_of_birth": PatternDefinition(
        name="DATE_OF_BIRTH",
        regex=re.compile(
            r"(?i)\b(?:dob|d\.o\.b\.?|date\s+of\s+birth|birth\s*date|born(?:\s+on)?)\W{0,5}"
            r"(?P<value>\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{2}-\d{2})"
        ),
        description="Dates of birth, when labelled 'DOB', 'date of birth' or 'born'.",
        false_positive_notes="Low. Needs the label and a numeric date. Dates written in words are not caught.",
    ),
    # --- Criminal justice (CJIS) ---
    "fbi_number": PatternDefinition(
        name="FBI_NUMBER",
        regex=re.compile(
            r"(?i)\b(?:fbi\s*(?:number|no\.?|#)|ucn|universal\s+control\s+number)\W{0,5}"
            r"(?P<value>(?=[A-Z0-9]*\d)[A-Z0-9]{6,9})\b"
        ),
        description="FBI Number / Universal Control Number, when labelled.",
        false_positive_notes="Low. Needs the label, and the value must contain a digit.",
    ),
    "state_id_number": PatternDefinition(
        name="STATE_ID_NUMBER",
        regex=re.compile(
            r"(?i)\b(?:sid|state\s+id(?:entification)?)\s*(?:number|no\.?|#)?\W{0,5}(?P<value>[A-Z]{0,2}\d{5,10})\b"
        ),
        description="State identification numbers (SID) from criminal history records, when labelled.",
        false_positive_notes="Low to moderate. 'SID' is also a short name and a common abbreviation in IT.",
    ),
    "drivers_license": PatternDefinition(
        name="DRIVERS_LICENSE",
        regex=re.compile(
            r"(?i)\b(?:driver'?s?\s+licen[sc]e|operator\s+licen[sc]e)\s*(?:number|no\.?|#)?\W{0,5}"
            r"(?P<value>(?=[A-Z0-9]*\d)[A-Z0-9]{5,15})\b"
        ),
        description="Driver's license numbers, when labelled. Formats differ by state.",
        false_positive_notes="Low. Needs the label, and the value must contain a digit.",
    ),
}

# Patterns checked only in LLM responses. Every input pattern above is also
# checked in responses; see OutputScanner for how the action is chosen.
OUTPUT_ONLY_PATTERNS: dict[str, PatternDefinition] = {
    "suspicious_url": PatternDefinition(
        name="SUSPICIOUS_URL",
        regex=re.compile(r"https?://(?:[a-zA-Z0-9-]+\.)+(?:test|example|invalid|localhost)\b"),
        description="Hallucinated or test URLs in the LLM response.",
        false_positive_notes="Low. Only flags known non-routable TLDs.",
    ),
}
