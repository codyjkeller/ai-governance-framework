"""Tests for the AI use case inventory checker."""

from datetime import date
from pathlib import Path

import pytest
import yaml

from ai_governance.inventory import check_entry, check_inventory, main, minimum_tier

ROOT = Path(__file__).parent.parent
INVENTORY = ROOT / "governance" / "ai_inventory.yaml"
POLICY = ROOT / "policies" / "generative_ai_aup.yaml"
ALLOWED = ["gpt-6-luna*", "claude-sonnet*"]
TODAY = date(2026, 11, 13)


def entry(**changes):
    base = {
        "id": "AI-100",
        "name": "Example",
        "owner": "Team Lead",
        "business_purpose": "Testing.",
        "status": "in_production",
        "provider": "OpenAI",
        "models": ["gpt-6-luna"],
        "via_proxy": True,
        "data_classes": ["internal"],
        "affects_individuals": False,
        "autonomy": "assistive",
        "audience": "internal",
        "risk_tier": 3,
        "approved_by": "CISO",
        "approved_on": date(2026, 10, 1),
        "next_review": date(2027, 10, 1),
    }
    base.update(changes)
    return base


def problems(**changes):
    return check_entry(entry(**changes), ALLOWED, TODAY)[0]


class TestShippedInventory:
    def test_the_example_inventory_passes(self):
        inventory = yaml.safe_load(INVENTORY.read_text())
        allowed = yaml.safe_load(POLICY.read_text())["global_settings"]["allowed_model_families"]
        assert check_inventory(inventory, allowed, TODAY) == ([], [])

    def test_command_reports_success(self, capsys):
        assert main([str(INVENTORY), "--policy", str(POLICY), "--allow-overdue"]) == 0
        assert "3 use cases checked: 0 problems" in capsys.readouterr().out


class TestMinimumTier:
    @pytest.mark.parametrize(
        ("changes", "expected"),
        [
            ({"data_classes": ["cji"]}, 1),
            ({"data_classes": ["internal", "phi"]}, 1),
            ({"affects_individuals": True}, 1),
            ({"autonomy": "autonomous"}, 1),
            ({"data_classes": ["pii"]}, 2),
            ({"data_classes": ["confidential"]}, 2),
            ({"audience": "external"}, 2),
            ({}, 3),
        ],
    )
    def test_tier_follows_the_answers(self, changes, expected):
        assert minimum_tier(entry(**changes))[0] == expected


class TestEntryChecks:
    def test_a_complete_entry_has_no_problems(self):
        assert problems() == []

    def test_under_rated_tier_is_a_problem(self):
        found = problems(data_classes=["cji"], risk_tier=3)
        assert any("must be 1 or stricter because it handles PHI or CJI" in text for text in found)

    def test_stricter_tier_than_needed_is_allowed(self):
        assert problems(risk_tier=1, human_oversight="Reviewed by a supervisor.", next_review=date(2027, 3, 1)) == []

    def test_tier_one_needs_human_oversight(self):
        found = problems(risk_tier=1, next_review=date(2027, 3, 1))
        assert found == ["a tier 1 use case must describe its human_oversight."]

    def test_missing_fields_are_listed(self):
        assert "missing 'owner'." in problems(owner="")

    @pytest.mark.parametrize(
        ("field", "value"),
        [("status", "live"), ("autonomy", "full"), ("audience", "everyone"), ("risk_tier", 4)],
    )
    def test_invalid_choices_are_problems(self, field, value):
        assert any(text.startswith(f"{field} is") for text in problems(**{field: value}))

    def test_unknown_data_class_is_a_problem(self):
        assert any("data_classes has 'secret'" in text for text in problems(data_classes=["secret"]))

    def test_model_must_be_on_the_approved_list_when_using_the_proxy(self):
        assert problems(models=["gpt-4"]) == ["model 'gpt-4' is not on the proxy's approved model list."]
        assert problems(models=["gpt-4"], via_proxy=False) == []

    def test_approved_entries_need_approval_details(self):
        found = problems(approved_by=None, next_review=None)
        assert "missing 'approved_by' (required once approved)." in found
        assert "missing 'next_review' (required once approved)." in found

    def test_proposed_entries_do_not_need_approval_details(self):
        assert problems(status="proposed", approved_by=None, approved_on=None, next_review=None) == []

    def test_review_date_must_be_inside_the_limit_for_the_tier(self):
        found = problems(risk_tier=2, data_classes=["pii"], next_review=date(2028, 6, 1))
        assert any("more than 366 days after approval for tier 2" in text for text in found)

    def test_overdue_review_is_reported_separately(self):
        found, overdue = check_entry(entry(approved_on=date(2025, 6, 1), next_review=date(2026, 6, 1)), ALLOWED, TODAY)
        assert found == []
        assert overdue == ["review was due 2026-06-01."]

    def test_dates_written_as_text_are_accepted(self):
        assert problems(approved_on="2026-10-01", next_review="2027-10-01") == []
        assert "next_review is not a date (use YYYY-MM-DD)." in problems(next_review="next spring")


class TestInventoryChecks:
    def test_duplicate_ids_are_a_problem(self):
        found, _ = check_inventory({"use_cases": [entry(), entry()]}, ALLOWED, TODAY)
        assert found == ["AI-100: this id is used more than once."]

    @pytest.mark.parametrize("inventory", [None, {}, {"use_cases": []}, {"use_cases": "none"}, []])
    def test_empty_or_malformed_file_is_a_problem(self, inventory):
        assert check_inventory(inventory, ALLOWED, TODAY)[0]

    def test_entry_that_is_not_a_mapping_is_a_problem(self):
        found, _ = check_inventory({"use_cases": ["AI-1"]}, ALLOWED, TODAY)
        assert found == ["entry 1: entry is not a mapping of fields."]


class TestCommand:
    def write(self, tmp_path, **changes):
        path = tmp_path / "inventory.yaml"
        path.write_text(yaml.safe_dump({"use_cases": [entry(**changes)]}))
        return str(path)

    def test_problems_fail_the_command(self, tmp_path, capsys):
        assert main([self.write(tmp_path, owner=""), "--policy", str(POLICY)]) == 1
        assert "PROBLEM     AI-100: missing 'owner'." in capsys.readouterr().out

    def test_overdue_review_fails_unless_allowed(self, tmp_path, capsys):
        path = self.write(tmp_path, approved_on=date(2024, 1, 1), next_review=date(2025, 1, 1))
        assert main([path, "--policy", str(POLICY)]) == 1
        assert "REVIEW DUE  AI-100" in capsys.readouterr().out
        assert main([path, "--policy", str(POLICY), "--allow-overdue"]) == 0

    def test_missing_file_fails_cleanly(self, tmp_path, capsys):
        assert main([str(tmp_path / "nope.yaml"), "--policy", str(POLICY)]) == 1
        assert "Could not read the files" in capsys.readouterr().out
