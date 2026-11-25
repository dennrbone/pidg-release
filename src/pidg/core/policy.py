from __future__ import annotations

from typing import Any

from jsonschema import Draft202012Validator, ValidationError

from pidg.core.models import Decision, Policy, Task, Verdict


def check_schema(schema: dict[str, Any]) -> None:
    # Remote refs are deliberately unsupported: validation must not fetch attacker URLs.
    def check(item: Any) -> None:
        if isinstance(item, dict):
            for key, val in item.items():
                if key in {"$ref", "$dynamicRef"} and (
                    not isinstance(val, str) or not val.startswith("#")
                ):
                    raise ValueError("external schema reference")
                check(val)
        elif isinstance(item, list):
            for val in item:
                check(val)

    check(schema)
    Draft202012Validator.check_schema(schema)


def validate_schema(schema: dict[str, Any], value: Any) -> None:
    check_schema(schema)
    Draft202012Validator(schema).validate(value)


class PolicyEngine:
    def __init__(self, policy: Policy | None) -> None:
        self.policy = policy.model_copy(deep=True) if policy else None
        if policy:
            for rule in policy.rules.values():
                check_schema(rule.argument_schema)

    def authorize(
        self,
        task: Task,
        tool: str,
        arguments: dict[str, Any],
        labels: frozenset[str],
        trusted_arguments: bool = False,
    ) -> Verdict:
        version = self.policy.version if self.policy else "missing"

        def verdict(decision: Decision, reason: str) -> Verdict:
            return Verdict(decision=decision, reason_code=reason, policy_version=version)

        if self.policy is None:
            return verdict(Decision.DENY, "POLICY_UNAVAILABLE")
        if task.principal_id not in self.policy.principals:
            return verdict(Decision.DENY, "PRINCIPAL_DENIED")
        rule = self.policy.rules.get(tool)
        if rule is None or tool not in task.allowed_tools:
            return verdict(Decision.DENY, "TOOL_DENIED")
        if rule.capability not in task.capabilities or rule.purpose != task.purpose:
            return verdict(Decision.DENY, "TASK_SCOPE_DENIED")
        try:
            validate_schema(rule.argument_schema, arguments)
        except (ValidationError, ValueError):
            return verdict(Decision.DENY, "ARGUMENT_SCOPE_DENIED")
        if not labels.issubset(set(rule.allowed_labels)):
            return verdict(Decision.DENY, "DATA_CLASSIFICATION_DENIED")
        if rule.trusted_arguments and not trusted_arguments:
            return verdict(Decision.DENY, "UNTRUSTED_ARGUMENTS")
        if rule.approval:
            return verdict(Decision.REQUIRE_APPROVAL, "APPROVAL_REQUIRED")
        return verdict(Decision.ALLOW, "TASK_AUTHORIZED")
