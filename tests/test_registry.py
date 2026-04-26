from __future__ import annotations

from secaudit.registry import parse_module_csv, resolve_module_plan


def test_parse_module_csv_resolves_aliases() -> None:
    assert parse_module_csv("tls, js, cors") == ("tls", "javascript", "api")


def test_resolve_module_plan_uses_profile_and_skip() -> None:
    plan = resolve_module_plan(profile="standard", skip=("api",))
    assert tuple(module.slug for module in plan) == ("dns", "tls", "headers", "csp", "cookies", "static")


def test_resolve_module_plan_only_overrides_profile() -> None:
    plan = resolve_module_plan(profile="deep", only=("tls", "headers"))
    assert tuple(module.slug for module in plan) == ("tls", "headers")
