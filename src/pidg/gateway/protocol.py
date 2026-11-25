from __future__ import annotations

from pathlib import Path
from typing import TypeVar

from pidg.core.models import GatewayConfig, Policy, StrictModel, Task, parse_json
from pidg.core.policy import PolicyEngine
from pidg.gateway.registry import Registry

T = TypeVar("T", bound=StrictModel)


def read_model(path: Path, model: type[T]) -> T:
    raw = path.read_text()

    parse_json(raw)
    return model.model_validate_json(raw)


def load_config(path: Path) -> tuple[GatewayConfig, Policy, Task, Registry]:
    config = read_model(path, GatewayConfig)
    base = path.resolve().parent
    policy = read_model(base / config.policy, Policy)
    PolicyEngine(policy)  # Reject invalid policy schemas before starting any upstream process.
    task = read_model(base / config.task, Task)
    registry = read_model(base / config.registry, Registry)
    for entry in registry.entries:
        if entry.server not in config.upstreams:
            raise ValueError("registry references unconfigured upstream")
    return config, policy, task, registry
