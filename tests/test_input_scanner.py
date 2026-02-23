"""Tests for the input scanner.

Each pattern gets at least one true-positive test (should match)
and one true-negative test (should NOT match or should not cause
incorrect action).
"""


class TestSSNDetection:
    def test_blocks_standard_ssn(self, input_scanner):
        result = input_scanner.scan("My SSN is 123-45-6789")
        assert result.status == "BLOCKED"
        assert any(v["type"] == "SSN" for v in result.violations)

    def test_ignores_non_ssn_dashed_numbers(self, input_scanner):
        result = input_scanner.scan("Call reference 999-99-99")
        # This doesn't match the SSN pattern (only 2 digits in last group)
        assert not any(v["type"] == "SSN" for v in result.violations)


class TestEmailDetection:
    def test_redacts_email_address(self, input_scanner):
        result = input_scanner.scan("Contact john.doe@example.com for details")
        assert result.status == "REDACTED"
        assert "[EMAIL_REDACTED]" in result.text
        assert "john.doe@example.com" not in result.text

    def test_ignores_non_email_at_signs(self, input_scanner):
        result = input_scanner.scan("variable @property decorator in Python")
        assert not any(v["type"] == "EMAIL" for v in result.violations)


class TestPhoneDetection:
    def test_redacts_us_phone(self, input_scanner):
        result = input_scanner.scan("Call me at (555) 123-4567")
        assert result.status == "REDACTED"
        assert any(v["type"] == "PHONE_US" for v in result.violations)

    def test_redacts_phone_with_country_code(self, input_scanner):
        result = input_scanner.scan("Phone: +1-555-123-4567")
        assert any(v["type"] == "PHONE_US" for v in result.violations)


class TestCreditCardDetection:
    def test_blocks_credit_card_dashed(self, input_scanner):
        result = input_scanner.scan("Card: 4111-1111-1111-1111")
        assert result.status == "BLOCKED"
        assert any(v["type"] == "CREDIT_CARD" for v in result.violations)

    def test_blocks_credit_card_spaces(self, input_scanner):
        result = input_scanner.scan("Card: 4111 1111 1111 1111")
        assert result.status == "BLOCKED"
        assert any(v["type"] == "CREDIT_CARD" for v in result.violations)

    def test_blocks_credit_card_no_separator(self, input_scanner):
        result = input_scanner.scan("Card: 4111111111111111")
        assert result.status == "BLOCKED"


class TestAWSKeyDetection:
    def test_blocks_aws_access_key(self, input_scanner):
        result = input_scanner.scan("Key: AKIAIOSFODNN7EXAMPLE")
        assert result.status == "BLOCKED"
        assert any(v["type"] == "AWS_ACCESS_KEY" for v in result.violations)

    def test_blocks_asia_prefixed_key(self, input_scanner):
        result = input_scanner.scan("Temp key: ASIA1234567890ABCDEF")
        assert result.status == "BLOCKED"

    def test_ignores_non_aws_prefix(self, input_scanner):
        result = input_scanner.scan("Token: ABCD1234567890ABCDEF")
        assert not any(v["type"] == "AWS_ACCESS_KEY" for v in result.violations)


class TestPrivateKeyDetection:
    def test_blocks_rsa_key_header(self, input_scanner):
        result = input_scanner.scan("-----BEGIN RSA PRIVATE KEY-----")
        assert result.status == "BLOCKED"
        assert any(v["type"] == "PRIVATE_KEY_BLOCK" for v in result.violations)

    def test_blocks_ec_key_header(self, input_scanner):
        result = input_scanner.scan("-----BEGIN EC PRIVATE KEY-----")
        assert result.status == "BLOCKED"


class TestGenericAPIKeyDetection:
    def test_blocks_api_key_assignment(self, input_scanner):
        result = input_scanner.scan("api_key=abcdefghijklmnopqrstuvwxyz")
        assert result.status == "BLOCKED"
        assert any(v["type"] == "API_KEY_GENERIC" for v in result.violations)

    def test_blocks_secret_assignment(self, input_scanner):
        result = input_scanner.scan("secret: my_super_secret_value_12345")
        assert result.status == "BLOCKED"


class TestIPAddressDetection:
    def test_redacts_valid_ip(self, input_scanner):
        result = input_scanner.scan("Server at 192.168.1.55")
        assert result.status == "REDACTED"
        assert "[IP_ADDRESS_REDACTED]" in result.text

    def test_ignores_invalid_octets(self, input_scanner):
        """The improved pattern should NOT match octets > 255."""
        result = input_scanner.scan("Value: 999.999.999.999")
        assert not any(v["type"] == "IP_ADDRESS" for v in result.violations)

    def test_valid_boundary_ip(self, input_scanner):
        result = input_scanner.scan("IP: 255.255.255.255")
        assert any(v["type"] == "IP_ADDRESS" for v in result.violations)


class TestICD10Detection:
    def test_redacts_icd10_code(self, input_scanner):
        result = input_scanner.scan("Diagnosis: J01.90 (Acute sinusitis)")
        assert any(v["type"] == "ICD10_CODE" for v in result.violations)

    def test_redacts_icd10_without_decimal(self, input_scanner):
        """ICD-10 codes can be 3 chars without a decimal."""
        result = input_scanner.scan("Code: J01")
        assert any(v["type"] == "ICD10_CODE" for v in result.violations)


class TestDEANumberDetection:
    def test_redacts_dea_number(self, input_scanner):
        result = input_scanner.scan("DEA: AB1234567")
        assert any(v["type"] == "DEA_NUMBER" for v in result.violations)


class TestCleanPrompt:
    def test_clean_prompt_passes_through(self, input_scanner):
        prompt = "What is the capital of France?"
        result = input_scanner.scan(prompt)
        assert result.status == "CLEAN"
        assert result.text == prompt
        assert result.violations == []


class TestMultipleViolations:
    def test_mixed_block_and_redact(self, input_scanner):
        """If both BLOCK and REDACT violations are found, BLOCK wins."""
        prompt = "SSN: 123-45-6789, Email: test@example.com"
        result = input_scanner.scan(prompt)
        assert result.status == "BLOCKED"
        assert len(result.violations) >= 2
