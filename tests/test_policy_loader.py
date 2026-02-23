"""Tests for the policy loader.

Covers: valid policy loading, missing file fallback, malformed YAML,
and helper functions for enforcement mode, model allowlisting, and rule lookup.
"""

from pathlib import Path

import pytest

from ai_governance.policy.loader import (
    DEFAULT_POLICY,
    get_allowed_models,
    get_data_rule,
    get_enforcement_mode,
    load_policy,
)


class TestLoadPolicy:
    def test_loads_valid_policy(self, tmp_path):
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(
            "global_settings:\n"
            "  policy_version: '1.0'\n"
            "  enforcement_mode: 'blocking'\n"
            "data_rules:\n"
            "  ssn:\n"
            "    sensitivity: 'CRITICAL'\n"
            "    action: 'BLOCK'\n"
        )
        policy = load_policy(policy_file)
        assert policy["global_settings"]["policy_version"] == "1.0"
        assert policy["data_rules"]["ssn"]["action"] == "BLOCK"

    def test_falls_back_on_missing_file(self, tmp_path):
        policy = load_policy(tmp_path / "nonexistent.yaml")
        assert policy == DEFAULT_POLICY

    def test_falls_back_on_malformed_yaml(self, tmp_path):
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("{{{{not valid yaml")
        policy = load_policy(bad_file)
        assert policy == DEFAULT_POLICY

    def test_falls_back_if_yaml_is_not_dict(self, tmp_path):
        list_file = tmp_path / "list.yaml"
        list_file.write_text("- item1\n- item2\n")
        policy = load_policy(list_file)
        assert policy == DEFAULT_POLICY


class TestGetEnforcementMode:
    def test_returns_yaml_value(self):
        policy = {"global_settings": {"enforcement_mode": "monitoring"}}
        assert get_enforcement_mode(policy) == "monitoring"

    def test_env_override_takes_precedence(self):
        policy = {"global_settings": {"enforcement_mode": "monitoring"}}
        assert get_enforcement_mode(policy, env_override="blocking") == "blocking"

    def test_defaults_to_blocking(self):
        assert get_enforcement_mode({}) == "blocking"


class TestGetAllowedModels:
    def test_returns_model_list(self):
        policy = {"global_settings": {"allowed_model_families": ["gpt-4*", "claude-3*"]}}
        assert get_allowed_models(policy) == ["gpt-4*", "claude-3*"]

    def test_returns_empty_if_missing(self):
        assert get_allowed_models({}) == []


class TestGetDataRule:
    def test_returns_defined_rule(self):
        policy = {"data_rules": {"ssn": {"action": "BLOCK", "sensitivity": "CRITICAL"}}}
        rule = get_data_rule(policy, "ssn")
        assert rule["action"] == "BLOCK"
        assert rule["sensitivity"] == "CRITICAL"

    def test_returns_default_for_unknown_rule(self):
        rule = get_data_rule({}, "unknown_pattern")
        assert rule["action"] == "REDACT"
        assert rule["sensitivity"] == "HIGH"

    def test_case_insensitive_lookup(self):
        policy = {"data_rules": {"email": {"action": "REDACT", "sensitivity": "MEDIUM"}}}
        rule = get_data_rule(policy, "EMAIL")
        assert rule["action"] == "REDACT"
