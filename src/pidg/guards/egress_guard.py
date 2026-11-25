from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlsplit

from pidg.core.models import Rule, canonical
from pidg.guards.input_guard import secret_labels


def normalize_destination(value: str) -> str:
    if value.startswith("mock://"):
        if value not in {"mock://public", "mock://forbidden"}:
            raise ValueError("unknown mock destination")
        return value
    if any(c.isspace() or ord(c) < 32 for c in value) or "\\" in value or "%" in value:
        raise ValueError("ambiguous URL")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("HTTPS without userinfo required")
    if parsed.query or parsed.fragment or parsed.port not in {None, 443}:
        raise ValueError("query/fragment/nonstandard port denied")
    host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    if host in {"localhost", "localhost.localdomain"} or host.endswith((".localhost", ".local")):
        raise ValueError("local destination")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if "." not in host or all(c.isdigit() or c == "." for c in host):
            raise ValueError("ambiguous hostname") from None
    else:
        if not address.is_global:
            raise ValueError("private destination")
        host = f"[{address}]" if address.version == 6 else str(address)
    return f"https://{host}{parsed.path or '/'}"


class EgressGuard:
    def check(
        self,
        rule: Rule,
        args: dict[str, Any],
        labels: frozenset[str],
        *,
        protected_values: tuple[str, ...] = (),
    ) -> str | None:
        if rule.action != "send":
            return None
        if (
            "secret" in labels
            or "confidential" in labels
            or secret_labels(canonical(args), protected_values=protected_values)
        ):
            return "SECRET_EGRESS_DENIED"
        if not rule.destination_field or not rule.destinations:
            return "DESTINATION_NOT_CONFIGURED"
        value = args.get(rule.destination_field)
        if not isinstance(value, str):
            return "INVALID_DESTINATION"
        try:
            normalized = normalize_destination(value)
            allowed = {normalize_destination(v) for v in rule.destinations}
        except ValueError:
            return "INVALID_DESTINATION"
        return None if normalized in allowed else "DESTINATION_DENIED"
