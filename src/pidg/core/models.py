from __future__ import annotations

import hashlib
import json
import math
import sys
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, allow_inf_nan=False)


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class Verdict(StrictModel):
    decision: Decision
    reason_code: str
    policy_version: str


def parse_json(text: str | bytes | bytearray) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(value: str) -> Any:
        raise ValueError("nonfinite JSON number")

    def finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError("JSON numeric overflow")
        return parsed

    return json.loads(
        text, object_pairs_hook=unique, parse_constant=reject_constant, parse_float=finite_float
    )


def canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


class Task(StrictModel):
    task_id: str = Field(min_length=1)
    principal_id: str = Field(min_length=1)
    purpose: str = Field(min_length=1)
    allowed_tools: tuple[str, ...]
    capabilities: tuple[str, ...]
    # Operator supplied exact bindings are the only trusted argument values.
    bindings: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)


class Rule(StrictModel):
    action: Literal["read", "write", "send", "memory", "execute"]
    capability: str = Field(min_length=1)
    purpose: str = Field(min_length=1)
    argument_schema: dict[str, Any] = Field(default_factory=lambda: {"type": "object"})
    approval: bool = False
    trusted_arguments: bool = False
    allowed_labels: tuple[str, ...] = ("public", "unverified")
    destinations: tuple[str, ...] = ()
    destination_field: str | None = None
    memory_namespace_field: str | None = None


class Policy(StrictModel):
    version: str = Field(min_length=1)
    principals: tuple[str, ...]
    rules: dict[str, Rule]
    contract_changes: Literal["deny", "require_repin"] = "deny"


class UpstreamConfig(StrictModel):
    command: str = Field(min_length=1)
    args: tuple[str, ...] = ()
    cwd: str | None = None


class GatewayConfig(StrictModel):
    policy: str
    task: str
    registry: str
    audit: str
    approvals: str
    upstreams: dict[str, UpstreamConfig]
    mode: Literal["monitor", "protect", "strict"] = "strict"
    timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    enable_resources: bool = False
    enable_prompts: bool = False
    require_atomic_contracts: bool = False
    reviewed_read_fallback: bool = False
    scope_labels_to_bound_arguments: bool = False
    protected_values: tuple[str, ...] = Field(default=(), max_length=128)

    @model_validator(mode="after")
    def validate_protected_values(self) -> GatewayConfig:
        if any(not 8 <= len(value) <= 1024 for value in self.protected_values):
            raise ValueError("protected values must contain 8 to 1024 characters")
        return self

    @model_validator(mode="after")
    def validate_mode(self) -> GatewayConfig:
        if self.reviewed_read_fallback and (
            not self.require_atomic_contracts or self.mode != "strict"
        ):
            raise ValueError("reviewed read fallback requires strict atomic executor")
        if self.mode == "monitor":
            for upstream in self.upstreams.values():
                if (
                    upstream.args != ("-I", "-m", "pidg.research.mock_server")
                    or Path(upstream.command).resolve() != Path(sys.executable).resolve()
                ):
                    raise ValueError("monitor requires bundled isolated mock upstream")
        return self
