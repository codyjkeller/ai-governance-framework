"""AI use case inventory checker.

The inventory (governance/ai_inventory.yaml) lists every way the organization
uses AI: who owns it, what data it touches and how much risk it carries.
This module checks that the file is complete and that each entry's risk tier
is at least as strict as its own answers require.

It reads files and prints a report. It does not change the proxy's behavior.

Usage:
    ai-gov-inventory                      # checks governance/ai_inventory.yaml
    ai-gov-inventory path/to/file.yaml
"""

import argparse
import fnmatch
import sys
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from ai_governance.policy.loader import get_allowed_models

DEFAULT_INVENTORY = Path("governance/ai_inventory.yaml")
DEFAULT_POLICY = Path("policies/generative_ai_aup.yaml")

STATUSES = {"proposed", "approved", "in_production", "retired"}
DATA_CLASSES = {"public", "internal", "confidential", "pii", "phi", "cji"}
AUTONOMY_LEVELS = {"assistive", "human_approves", "autonomous"}
AUDIENCES = {"internal", "external"}
TIERS = {1, 2, 3}

REQUIRED_FIELDS = (
    "id",
    "name",
    "owner",
    "business_purpose",
    "status",
    "provider",
    "models",
    "via_proxy",
    "data_classes",
    "affects_individuals",
    "autonomy",
    "audience",
    "risk_tier",
)
# Once a use case is approved, someone has signed for it and set a review date.
APPROVAL_FIELDS = ("approved_by", "approved_on", "next_review")

# Longest time allowed between approval and the next review, in days, by tier.
MAX_REVIEW_DAYS = {1: 183, 2: 366, 3: 731}


def minimum_tier(entry: dict[str, Any]) -> tuple[int, str]:
    """The strictest tier an entry's own answers call for, and why.

    Tier 1 is the highest risk. See governance/risk_tiering.md.
    """
    data = {str(item).lower() for item in entry.get("data_classes") or []}
    if data & {"phi", "cji"}:
        return 1, "it handles PHI or CJI"
    if entry.get("affects_individuals") is True:
        return 1, "it informs decisions about individuals"
    if entry.get("autonomy") == "autonomous":
        return 1, "it acts without a person approving each action"
    if data & {"pii", "confidential"}:
        return 2, "it handles PII or confidential data"
    if entry.get("audience") == "external":
        return 2, "its output goes outside the organization"
    return 3, "it uses only public or internal data"


def _as_date(value: Any) -> date | None:
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value))
    except ValueError:
        return None


def check_entry(entry: Any, allowed_models: list[str], today: date) -> tuple[list[str], list[str]]:
    """Check one inventory entry. Returns (problems, overdue reviews)."""
    if not isinstance(entry, dict):
        return ["entry is not a mapping of fields."], []

    problems = [f"missing '{field}'." for field in REQUIRED_FIELDS if entry.get(field) in (None, "", [])]
    overdue: list[str] = []

    def check_choice(field: str, valid: set[Any]) -> None:
        value = entry.get(field)
        if value is not None and value not in valid:
            problems.append(f"{field} is '{value}'. Valid: {sorted(valid)}")

    check_choice("status", STATUSES)
    check_choice("autonomy", AUTONOMY_LEVELS)
    check_choice("audience", AUDIENCES)
    check_choice("risk_tier", TIERS)

    for field in ("via_proxy", "affects_individuals"):
        if entry.get(field) is not None and not isinstance(entry[field], bool):
            problems.append(f"{field} must be true or false.")

    data_classes = entry.get("data_classes") or []
    if not isinstance(data_classes, list):
        problems.append("data_classes must be a list.")
        data_classes = []
    problems.extend(
        f"data_classes has '{item}'. Valid: {sorted(DATA_CLASSES)}" for item in data_classes if item not in DATA_CLASSES
    )

    models = entry.get("models") or []
    if not isinstance(models, list):
        problems.append("models must be a list.")
        models = []
    if entry.get("via_proxy") is True and allowed_models and entry.get("status") != "retired":
        problems.extend(
            f"model '{model}' is not on the proxy's approved model list."
            for model in models
            if not any(fnmatch.fnmatch(str(model).lower(), pattern.lower()) for pattern in allowed_models)
        )

    tier = entry.get("risk_tier")
    if tier in TIERS:
        needed, reason = minimum_tier(entry)
        if tier > needed:
            problems.append(f"risk_tier is {tier} but must be {needed} or stricter because {reason}.")
        if tier == 1 and not entry.get("human_oversight"):
            problems.append("a tier 1 use case must describe its human_oversight.")

    if entry.get("status") in {"approved", "in_production"}:
        problems.extend(
            f"missing '{field}' (required once approved)." for field in APPROVAL_FIELDS if not entry.get(field)
        )
        approved_on, next_review = _as_date(entry.get("approved_on")), _as_date(entry.get("next_review"))
        for field, parsed in (("approved_on", approved_on), ("next_review", next_review)):
            if entry.get(field) and parsed is None:
                problems.append(f"{field} is not a date (use YYYY-MM-DD).")
        if approved_on and next_review and tier in TIERS:
            if (next_review - approved_on).days > MAX_REVIEW_DAYS[tier]:
                problems.append(
                    f"next_review is more than {MAX_REVIEW_DAYS[tier]} days after approval for tier {tier}."
                )
        if next_review and next_review < today:
            overdue.append(f"review was due {next_review.isoformat()}.")

    return problems, overdue


def check_inventory(inventory: Any, allowed_models: list[str], today: date) -> tuple[list[str], list[str]]:
    """Check a whole inventory. Returns (problems, overdue reviews), each line naming its entry."""
    entries = inventory.get("use_cases") if isinstance(inventory, dict) else None
    if not isinstance(entries, list) or not entries:
        return ["the file must have a 'use_cases' list with at least one entry."], []

    problems: list[str] = []
    overdue: list[str] = []
    seen: set[str] = set()
    for position, entry in enumerate(entries, start=1):
        label = str(entry.get("id") or f"entry {position}") if isinstance(entry, dict) else f"entry {position}"
        if label in seen:
            problems.append(f"{label}: this id is used more than once.")
        seen.add(label)
        entry_problems, entry_overdue = check_entry(entry, allowed_models, today)
        problems.extend(f"{label}: {text}" for text in entry_problems)
        overdue.extend(f"{label}: {text}" for text in entry_overdue)
    return problems, overdue


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the AI use case inventory.")
    parser.add_argument("inventory", nargs="?", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument(
        "--policy", type=Path, default=DEFAULT_POLICY, help="Proxy policy file with the approved models."
    )
    parser.add_argument("--allow-overdue", action="store_true", help="Report overdue reviews without failing.")
    args = parser.parse_args(argv)

    try:
        inventory = yaml.safe_load(args.inventory.read_text())
        policy = yaml.safe_load(args.policy.read_text()) or {}
    except (OSError, yaml.YAMLError) as error:
        print(f"Could not read the files: {error}")
        return 1

    problems, overdue = check_inventory(inventory, get_allowed_models(policy), date.today())
    count = len(inventory.get("use_cases") or []) if isinstance(inventory, dict) else 0
    for line in problems:
        print(f"PROBLEM     {line}")
    for line in overdue:
        print(f"REVIEW DUE  {line}")
    failed = bool(problems) or (bool(overdue) and not args.allow_overdue)
    print(f"{count} use cases checked: {len(problems)} problems, {len(overdue)} overdue reviews.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
