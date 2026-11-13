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
VALID_ENFORCEMENT_MODES = {"blocking", "monitoring"}


class PolicyError(Exception):
    """The policy file is missing or invalid and strict loading was requested."""


def load_policy(policy_path: Path, strict: bool = False) -> dict[str, Any]:
    """Load and validate the YAML policy file.

    Args:
        policy_path: Path to the YAML policy file.
        strict: If True, a missing or invalid policy raises PolicyError
            instead of falling back. The server uses strict loading so a
            policy mistake stops the proxy instead of quietly weakening it.

    Returns:
        Parsed policy dictionary. When strict is False, falls back to
        DEFAULT_POLICY if the file is missing or invalid, logging a warning.

    Raises:
        PolicyError: Only when strict is True.
    """
    if strict:
        return _load_policy_strict(policy_path)

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


def _load_policy_strict(policy_path: Path) -> dict[str, Any]:
    """Load the policy, raising PolicyError that lists every problem found."""
    if not policy_path.exists():
        raise PolicyError(f"Policy file not found: {policy_path}")
    try:
        with open(policy_path) as f:
            policy = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise PolicyError(f"Policy file {policy_path} is not valid YAML: {e}") from e
    if not isinstance(policy, dict):
        raise PolicyError(f"Policy file {policy_path} must contain a YAML mapping at the top level.")

    problems = find_policy_problems(policy)
    if problems:
        raise PolicyError(f"Policy file {policy_path} is invalid:\n" + "\n".join(f"  - {p}" for p in problems))
    return policy


def find_policy_problems(policy: dict[str, Any]) -> list[str]:
    """Return a description of every invalid value in the policy (empty list = valid)."""
    # Imported here: the pattern registry is only needed for validation.
    from ai_governance.scanning.patterns import INPUT_PATTERNS

    problems: list[str] = []

    global_settings = policy.get("global_settings", {})
    if not isinstance(global_settings, dict):
        return ["global_settings must be a mapping."]
    mode = global_settings.get("enforcement_mode", "blocking")
    if mode not in VALID_ENFORCEMENT_MODES:
        problems.append(f"enforcement_mode is '{mode}'. Valid: {sorted(VALID_ENFORCEMENT_MODES)}")
    if not isinstance(global_settings.get("allow_non_text_content", False), bool):
        problems.append("allow_non_text_content must be true or false.")
    families = global_settings.get("allowed_model_families", [])
    if not isinstance(families, list) or not all(isinstance(item, str) and item for item in families):
        problems.append("allowed_model_families must be a list of text patterns.")

    data_rules = policy.get("data_rules", {})
    if not isinstance(data_rules, dict):
        return [*problems, "data_rules must be a mapping."]
    for rule_name, rule_config in data_rules.items():
        if str(rule_name).lower() not in INPUT_PATTERNS:
            # A misspelled rule name would leave the real pattern on its default action.
            problems.append(f"data_rules.{rule_name}: no detection pattern has this name.")
            continue
        if not isinstance(rule_config, dict):
            problems.append(f"data_rules.{rule_name} must be a mapping with 'action' and 'sensitivity'.")
            continue
        action = rule_config.get("action", "")
        if action not in VALID_ACTIONS:
            problems.append(f"data_rules.{rule_name}.action is '{action}'. Valid: {sorted(VALID_ACTIONS)}")
        sensitivity = rule_config.get("sensitivity", "")
        if sensitivity not in VALID_SENSITIVITIES:
            problems.append(
                f"data_rules.{rule_name}.sensitivity is '{sensitivity}'. Valid: {sorted(VALID_SENSITIVITIES)}"
            )
    return problems


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
    mode: str = policy.get("global_settings", {}).get("enforcement_mode", "blocking")
    return mode


def get_allowed_models(policy: dict[str, Any]) -> list[str]:
    """Return the list of allowed model family patterns from the policy.

    Args:
        policy: Loaded policy dictionary.

    Returns:
        List of glob-style model patterns (e.g., ['gpt-4*', 'claude-3*']).
        Empty list means all models are allowed.
    """
    models: list[str] = policy.get("global_settings", {}).get("allowed_model_families", [])
    return models


def get_data_rule(policy: dict[str, Any], rule_name: str) -> dict[str, str]:
    """Look up a single data rule from the policy by name.

    Args:
        policy: Loaded policy dictionary.
        rule_name: Lowercase rule key (e.g., 'ssn', 'email').

    Returns:
        Dict with 'action' and 'sensitivity' keys.
        Falls back to REDACT/HIGH if the rule is not defined.
    """
    rule: dict[str, str] = policy.get("data_rules", {}).get(
        rule_name.lower(),
        {"action": "REDACT", "sensitivity": "HIGH"},
    )
    return rule


def get_allow_non_text_content(policy: dict[str, Any]) -> bool:
    """Whether images, audio and files may be sent to the model.

    They cannot be scanned by pattern matching, so the default is no.
    """
    return policy.get("global_settings", {}).get("allow_non_text_content", False) is True
