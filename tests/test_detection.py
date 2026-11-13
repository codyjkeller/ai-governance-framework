"""Tests for detection accuracy: what must be caught, and what must be left alone.

Also covers response scanning following the policy file.
"""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ai_governance.config import Settings
from ai_governance.policy.loader import PolicyError, load_policy
from ai_governance.scanning.output_scanner import OutputScanner
from ai_governance.scanning.patterns import INPUT_PATTERNS, passes_dea_checksum, passes_luhn
from ai_governance.server import create_app

POLICY = Path(__file__).parent.parent / "policies" / "generative_ai_aup.yaml"
HEADERS = {"X-Governance-API-Key": "k1"}

# Built at run time so secret scanners do not flag this file.
GITHUB_TOKEN = "ghp_" + "a1B2" * 9
LLM_KEY = "sk-proj-" + "A1b2" * 12
SLACK_TOKEN = "xoxb-" + "1234567890-abcdefghij"
GOOGLE_KEY = "AIza" + "S" * 35
STRIPE_KEY = "sk_live_" + "a1" * 12
JWT = ".".join(["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV"])


def types(result):
    return {v["type"] for v in result.violations}


class TestSecretsThatUsedToBeMissed:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("-----BEGIN PRIVATE KEY-----", "PRIVATE_KEY_BLOCK"),
            ("-----BEGIN ENCRYPTED PRIVATE KEY-----", "PRIVATE_KEY_BLOCK"),
            ("-----BEGIN PGP PRIVATE KEY BLOCK-----", "PRIVATE_KEY_BLOCK"),
            (f"token {GITHUB_TOKEN}", "GITHUB_TOKEN"),
            (f"OPENAI_API_KEY={LLM_KEY}", "LLM_API_KEY"),
            (f"slack: {SLACK_TOKEN}", "SLACK_TOKEN"),
            (f"maps key {GOOGLE_KEY}", "GOOGLE_API_KEY"),
            (f"stripe {STRIPE_KEY}", "STRIPE_KEY"),
            (f"session {JWT}", "JWT"),
            ("Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345", "BEARER_TOKEN"),
        ],
    )
    def test_blocked(self, input_scanner, text, expected):
        result = input_scanner.scan(text)
        assert result.status == "BLOCKED"
        assert expected in types(result)

    def test_public_key_header_is_not_a_secret(self, input_scanner):
        assert input_scanner.scan("-----BEGIN PUBLIC KEY-----").status == "CLEAN"

    def test_ordinary_words_are_not_keys(self, input_scanner):
        text = "Our risk-assessment-of-the-vendor-landscape is due. The bearer of this letter is Sam."
        assert input_scanner.scan(text).status == "CLEAN"


class TestSSN:
    @pytest.mark.parametrize("text", ["SSN 123456789", "ssn: 123 45 6789", "Social Security number is 078051120"])
    def test_labelled_ssn_without_dashes_is_blocked(self, input_scanner, text):
        result = input_scanner.scan(text)
        assert result.status == "BLOCKED"
        assert "SSN_UNFORMATTED" in types(result)

    def test_unlabelled_nine_digits_are_left_alone(self, input_scanner):
        assert "SSN_UNFORMATTED" not in types(input_scanner.scan("Order 123456789 shipped."))

    @pytest.mark.parametrize("number", ["000-12-3456", "666-12-3456", "912-34-5678", "123-00-4567", "123-45-0000"])
    def test_numbers_never_issued_are_not_ssns(self, input_scanner, number):
        assert "SSN" not in types(input_scanner.scan(f"ref {number}"))


class TestPaymentCards:
    @pytest.mark.parametrize(
        "card", ["4111111111111111", "4111-1111-1111-1111", "3782 822463 10005", "378282246310005"]
    )
    def test_valid_card_numbers_are_blocked(self, input_scanner, card):
        result = input_scanner.scan(f"card {card}")
        assert result.status == "BLOCKED"
        assert "CREDIT_CARD" in types(result)

    @pytest.mark.parametrize("number", ["1234567812345678", "4111111111111112", "2026 1113 0000 0001"])
    def test_sixteen_digits_that_fail_the_check_digit_are_left_alone(self, input_scanner, number):
        assert "CREDIT_CARD" not in types(input_scanner.scan(f"tracking number {number}"))

    def test_luhn(self):
        assert passes_luhn("4111 1111 1111 1111")
        assert not passes_luhn("4111 1111 1111 1112")
        assert not passes_luhn("1234")


class TestMedical:
    @pytest.mark.parametrize("text", ["Take vitamin B12 daily.", "Meet in room A10.", "Model X15 is in aisle C04."])
    def test_everyday_text_is_not_a_diagnosis_code(self, input_scanner, text):
        result = input_scanner.scan(text)
        assert result.status == "CLEAN"
        assert result.text == text

    @pytest.mark.parametrize("text", ["Diagnosis: J01", "ICD-10 I10", "dx E11", "Result was E11.9", "code: J01.90"])
    def test_diagnosis_codes_are_still_caught(self, input_scanner, text):
        assert "ICD10_CODE" in types(input_scanner.scan(text))

    def test_only_the_code_is_redacted_not_its_label(self, input_scanner):
        result = input_scanner.scan("Diagnosis: J01 confirmed")
        assert result.text == "Diagnosis: [ICD10_CODE_REDACTED] confirmed"

    def test_dea_number_needs_a_correct_check_digit(self, input_scanner):
        assert passes_dea_checksum("AB1234563")
        assert not passes_dea_checksum("AB1234567")
        assert "DEA_NUMBER" not in types(input_scanner.scan("Part AB1234567"))

    def test_medical_record_number(self, input_scanner):
        result = input_scanner.scan("Patient MRN: 00123456 admitted")
        assert result.text == "Patient MRN: [MEDICAL_RECORD_NUMBER_REDACTED] admitted"
        assert input_scanner.scan("MRN unknown").status == "CLEAN"

    def test_date_of_birth(self, input_scanner):
        result = input_scanner.scan("DOB 01/02/1960, seen 03/04/2026")
        assert result.text == "DOB [DATE_OF_BIRTH_REDACTED], seen 03/04/2026"


class TestCriminalJustice:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("FBI number 123456AB7", "FBI_NUMBER"),
            ("UCN: E7X2K9M1P", "FBI_NUMBER"),
            ("SID CA12345678", "STATE_ID_NUMBER"),
            ("state id number: 0987654", "STATE_ID_NUMBER"),
        ],
    )
    def test_criminal_history_identifiers_are_blocked(self, input_scanner, text, expected):
        result = input_scanner.scan(text)
        assert result.status == "BLOCKED"
        assert expected in types(result)

    def test_drivers_license_is_redacted(self, input_scanner):
        result = input_scanner.scan("driver's license D1234567")
        assert result.text == "driver's license [DRIVERS_LICENSE_REDACTED]"

    @pytest.mark.parametrize("text", ["Sid said hello.", "FBI number unknown.", "A driver license is required."])
    def test_labels_without_a_number_are_left_alone(self, input_scanner, text):
        assert input_scanner.scan(text).status == "CLEAN"


class TestEveryPatternHasAPolicyRule:
    def test_shipped_policy_names_every_pattern(self, sample_policy):
        assert set(INPUT_PATTERNS) == set(sample_policy["data_rules"])


def policy_with(tmp_path, extra):
    path = tmp_path / "policy.yaml"
    text = POLICY.read_text()
    assert text.count("\noutput_rules:\n") == 1
    path.write_text(text.replace("\noutput_rules:\n", "\noutput_rules:\n" + extra))
    return path


EMAIL_REDACT = "  email:\n    action: REDACT\n"


class TestResponseScanningFollowsPolicy:
    def test_secrets_blocked_in_prompts_are_blocked_in_replies(self, output_scanner):
        for text in (f"use {GITHUB_TOKEN}", "-----BEGIN PRIVATE KEY-----", "SSN 123456789"):
            assert output_scanner.scan(text).status == "BLOCKED"

    def test_redact_level_data_is_allowed_in_replies_by_default(self, output_scanner):
        text = "Write to help@example.org from 10.0.0.1."
        result = output_scanner.scan(text)
        assert result.status == "CLEAN"
        assert result.text == text

    def test_policy_can_redact_in_replies(self, tmp_path):
        scanner = OutputScanner(load_policy(policy_with(tmp_path, EMAIL_REDACT), strict=True))
        result = scanner.scan("Write to help@example.org.")
        assert result.status == "REDACTED"
        assert result.text == "Write to [EMAIL_REDACTED]."
        assert types(result) == {"LEAKED_EMAIL"}

    def test_policy_can_allow_what_would_be_blocked(self, tmp_path):
        policy = load_policy(POLICY, strict=True)
        policy["output_rules"]["suspicious_url"] = {"action": "ALLOW"}
        assert OutputScanner(policy).scan("See https://api.test.test").status == "CLEAN"

    def test_a_misspelled_response_rule_stops_startup(self, tmp_path):
        with pytest.raises(PolicyError, match="output_rules"):
            load_policy(policy_with(tmp_path, "  emial:\n    action: REDACT\n"), strict=True)
        with pytest.raises(PolicyError, match="output_rules"):
            load_policy(policy_with(tmp_path, "  email:\n    action: REDAKT\n"), strict=True)


def make_client(tmp_path, policy_path):
    settings = Settings(
        llm_api_key="sk-test-not-a-real-key-for-unit-tests-only",
        policy_path=policy_path,
        audit_log_path=tmp_path / "audit.jsonl",
        rate_limit=0,
        proxy_api_keys=["app:k1"],
        audit_hmac_key="test-signing-key-not-a-real-secret-000000",
        tls_terminated_upstream=True,
    )
    return TestClient(create_app(settings=settings))


def ask(client):
    body = {"model": "gpt-4", "messages": [{"role": "user", "content": "Who do I contact?"}]}
    return client.post("/v1/chat/completions", json=body, headers=HEADERS)


class TestResponseRedactionThroughTheProxy:
    def test_reply_is_redacted_and_logged(self, tmp_path, upstream):
        upstream.reply = "Write to help@example.org."
        response = ask(make_client(tmp_path, policy_with(tmp_path, EMAIL_REDACT)))
        assert response.status_code == 200
        assert response.json()["choices"][0]["message"]["content"] == "Write to [EMAIL_REDACTED]."
        entries = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
        assert any(e["event_type"] == "OUTPUT_SCAN" and e["status"] == "REDACTED" for e in entries)

    def test_monitoring_mode_returns_the_reply_unchanged(self, tmp_path, upstream):
        upstream.reply = "Write to help@example.org."
        policy = policy_with(tmp_path, EMAIL_REDACT)
        policy.write_text(policy.read_text().replace('enforcement_mode: "blocking"', 'enforcement_mode: "monitoring"'))
        response = ask(make_client(tmp_path, policy))
        assert response.json()["choices"][0]["message"]["content"] == "Write to help@example.org."

    def test_blocked_reply_is_still_suppressed(self, tmp_path, upstream):
        upstream.reply = f"The token is {GITHUB_TOKEN}"
        response = ask(make_client(tmp_path, POLICY))
        assert response.status_code == 502
        assert GITHUB_TOKEN not in response.text
