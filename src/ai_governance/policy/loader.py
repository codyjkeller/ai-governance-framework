"""YAML policy loader.

Loads and validates the governance policy file. Used by both input
and output scanners so the loading logic exists in exactly one place.
"""

import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# Default policy used when the YAML file is missing or unreadable.
# This ensures the proxy always enforces a minimum security baseline.
DEFAULT_POLICY: dict[str, Any] = {
    "global_settings": {
        "policy_version": "default",
        "enforcement_mode": "blocking",
        "allowed_model_families": [],
    },
    "data_rules": {
        "ssn": {"action": "BLOCK", "sensitivity": "CRITICAL"},
        "credit_card": {"action": "BLOCK", "sensitivity": "CRITICAL"},
        "aws_access_key": {"action": "BLOCK", "sensitivity": "CRITICAL"},
        "private_key_block": {"action": "BLOCK", "sensitivity": "CRITICAL"},
        "api_key_generic": {"action": "BLOCK", "sensitivity": "HIGH"},
        "email": {"action": "REDACT", "sensitivity": "MEDIUM"},
        "phone_us": {"action": "REDACT", "sensitivity": "MEDIUM"},
        "ip_address": {"action": "REDACT", "sensitivity": "MEDIUM"},
        "icd10_code": {"action": "REDACT", "sensitivity": "HIGH"},
        "dea_number": {"action": "REDACT", "sensitivity": "HIGH"},
    },
    "guardrails": {
        "hallucination_check": {"threshold": 0.85},
    },
}

VALID_ACTIONS = {"ALLOW", "REDACT", "BLOCK"}
VALID_SENSITIVITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def load_policy(policy_path: Path) -> dict[str, Any]:
    """Load and validate the YAML policy file.

    Args:
        policy_path: Path to the YAML policy file.

    Returns:
        Parsed policy dictionary. Falls back to DEFAULT_POLICY
        if the file is missing or invalid, logging a warning.
    """
    if not policy_path.exists():
        logger.warning(
            "Policy file not found at '%s'. Using default policy. "
            "This is acceptable for development but not for production.",
            policy_path,
        )
        return DEFAULT_POLICY.copy()

    try:
        with open(policy_path) as f:
            policy = yaml.safe_load(f)
    except yaml.YAMLError as e:
        logger.error("Failed to parse policy file '%s': %s. Using default policy.", policy_path, e)
        return DEFAULT_POLICY.copy()

    if not isinstance(policy, dict):
        logger.error("Policy file '%s' did not parse to a dict. Using default policy.", policy_path)
        return DEFAULT_POLICY.copy()

    _validate_policy(policy, policy_path)
    return policy


def _validate_policy(policy: dict[str, Any], policy_path: Path) -> None:
    """Log warnings for any invalid values in the policy file.

    Does not raise exceptions — the proxy should still start with
    a partially valid policy rather than refusing to boot.
    """
    data_rules = policy.get("data_rules", {})
    for rule_name, rule_config in data_rules.items():
        if not isinstance(rule_config, dict):
            logger.warning("Policy '%s': rule '%s' is not a dict, skipping.", policy_path, rule_name)
            continue

        action = rule_config.get("action", "")
        if action not in VALID_ACTIONS:
            logger.warning(
                "Policy '%s': rule '%s' has invalid action '%s'. Valid: %s",
                policy_path,
                rule_name,
                action,
                VALID_ACTIONS,
            )

        sensitivity = rule_config.get("sensitivity", "")
        if sensitivity not in VALID_SENSITIVITIES:
            logger.warning(
                "Policy '%s': rule '%s' has invalid sensitivity '%s'. Valid: %s",
                policy_path,
                rule_name,
                sensitivity,
                VALID_SENSITIVITIES,
            )


def get_enforcement_mode(policy: dict[str, Any], env_override: str = "") -> str:
    """Determine the active enforcement mode.

    Environment variable override takes precedence over the YAML value.

    Args:
        policy: Loaded policy dictionary.
        env_override: Value from ENFORCEMENT_MODE env var (empty = use YAML).

    Returns:
        'blocking' or 'monitoring'.
    """
    if env_override:
        return env_override
    return policy.get("global_settings", {}).get("enforcement_mode", "blocking")


def get_allowed_models(policy: dict[str, Any]) -> list[str]:
    """Return the list of allowed model family patterns from the policy.

    Args:
        policy: Loaded policy dictionary.

    Returns:
        List of glob-style model patterns (e.g., ['gpt-4*', 'claude-3*']).
        Empty list means all models are allowed.
    """
    return policy.get("global_settings", {}).get("allowed_model_families", [])


def get_data_rule(policy: dict[str, Any], rule_name: str) -> dict[str, str]:
    """Look up a single data rule from the policy by name.

    Args:
        policy: Loaded policy dictionary.
        rule_name: Lowercase rule key (e.g., 'ssn', 'email').

    Returns:
        Dict with 'action' and 'sensitivity' keys.
        Falls back to REDACT/HIGH if the rule is not defined.
    """
    return policy.get("data_rules", {}).get(
        rule_name.lower(),
        {"action": "REDACT", "sensitivity": "HIGH"},
    )
