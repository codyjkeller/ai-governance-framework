"""Tests for the output scanner.

Verifies that the output scanner catches data leakage in LLM responses
and allows clean responses through.
"""


class TestLeakedAPIKeyDetection:
    def test_blocks_leaked_api_key(self, output_scanner):
        response = "Here is the key: api_key=abcdefghijklmnopqrstuvwxyz"
        result = output_scanner.scan(response)
        assert result.status == "BLOCKED"
        assert any(v["type"] == "LEAKED_API_KEY" for v in result.violations)

    def test_blocks_leaked_secret(self, output_scanner):
        response = "The secret: secret=my_super_secret_value_12345"
        result = output_scanner.scan(response)
        assert result.status == "BLOCKED"


class TestLeakedSSNDetection:
    def test_blocks_leaked_ssn(self, output_scanner):
        response = "Found in training data: 123-45-6789"
        result = output_scanner.scan(response)
        assert result.status == "BLOCKED"
        assert any(v["type"] == "LEAKED_SSN" for v in result.violations)


class TestLeakedAWSKeyDetection:
    def test_blocks_leaked_aws_key(self, output_scanner):
        response = "The AWS key is AKIAIOSFODNN7EXAMPLE"
        result = output_scanner.scan(response)
        assert result.status == "BLOCKED"
        assert any(v["type"] == "LEAKED_AWS_KEY" for v in result.violations)


class TestSuspiciousURLDetection:
    def test_blocks_test_domain(self, output_scanner):
        response = "Visit https://api.test.test for more info"
        result = output_scanner.scan(response)
        assert result.status == "BLOCKED"
        assert any(v["type"] == "SUSPICIOUS_URL" for v in result.violations)

    def test_blocks_localhost_url(self, output_scanner):
        response = "Check http://service.localhost for details"
        result = output_scanner.scan(response)
        assert result.status == "BLOCKED"

    def test_allows_real_urls(self, output_scanner):
        response = "Visit https://docs.python.org for more info"
        result = output_scanner.scan(response)
        assert not any(v["type"] == "SUSPICIOUS_URL" for v in result.violations)


class TestCleanResponse:
    def test_clean_response_passes(self, output_scanner):
        response = "The capital of France is Paris."
        result = output_scanner.scan(response)
        assert result.status == "CLEAN"
        assert result.text == response
        assert result.violations == []
