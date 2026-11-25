from __future__ import annotations

from typing import Any

from pidg.core.models import Rule, canonical
from pidg.guards.input_guard import InputGuard


class MemoryGuard:
    def check(self, rule: Rule, args: dict[str, Any]) -> str | None:
        if rule.action != "memory":
            return None
        field = rule.memory_namespace_field
        if not field or args.get(field) != "observations":
            return "PROTECTED_MEMORY_NAMESPACE"
        if InputGuard().scan(canonical(args), "memory").findings:
            return "MEMORY_INSTRUCTION_DENIED"
        return None
