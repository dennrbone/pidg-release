from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import Field, model_validator

from pidg.core.models import StrictModel, digest
from pidg.core.policy import check_schema


def execution_contract(contract: dict[str, Any]) -> dict[str, Any]:
    """Presentation never changes schema, identity, annotations, version or execution metadata."""
    return {key: value for key, value in contract.items() if key not in {"description", "title"}}


class Entry(StrictModel):
    server: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,32}$")
    kind: Literal["tool", "resource", "prompt"] = "tool"
    name: str = Field(min_length=1, max_length=256)
    contract_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    contract: dict[str, Any]
    upstream_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    contract_version: int = Field(default=1, ge=1)

    @property
    def public_name(self) -> str:
        if self.kind == "resource":
            return f"pidg://{self.server}/{digest(self.name)}"
        return f"{self.server}__{self.kind}__{self.name}"

    @model_validator(mode="after")
    def check(self) -> Entry:
        if self.kind != "resource" and not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", self.name):
            raise ValueError("ambiguous upstream name")
        if digest(self.contract) != self.contract_hash:
            raise ValueError("registry contract hash mismatch")
        if self.contract.get("_meta", {}).get("pidg/contractVersion", 1) != self.contract_version:
            raise ValueError("registry contract version mismatch")
        if self.kind == "tool":
            check_schema(self.contract["inputSchema"])
            if "outputSchema" in self.contract:
                check_schema(self.contract["outputSchema"])
        return self


class Registry(StrictModel):
    entries: tuple[Entry, ...]

    @model_validator(mode="after")
    def unique(self) -> Registry:
        names = [e.public_name for e in self.entries]
        if len(names) != len(set(names)):
            raise ValueError("duplicate public identity")
        return self

    def get(self, name: str) -> Entry | None:
        return next((e for e in self.entries if e.public_name == name), None)
