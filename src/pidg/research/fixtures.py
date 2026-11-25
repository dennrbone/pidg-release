from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Literal

from pidg.core.models import GatewayConfig, Policy, Rule, Task, UpstreamConfig, canonical, digest
from pidg.gateway.registry import Entry, Registry
from pidg.research.mock_server import CONTRACTS, PROMPT, RESOURCE, initial_state


def create_demo(directory: Path, *, mode: str = "strict", atomic_contracts: bool = False) -> Path:
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    if any(directory.iterdir()):
        raise ValueError("init destination must be empty")
    upstream = UpstreamConfig(
        command=sys.executable, args=("-I", "-m", "pidg.research.mock_server"), cwd=str(directory)
    )
    entries = [
        Entry(
            server="mock",
            kind="tool",
            name=c["name"],
            contract=c,
            contract_hash=digest(c),
            upstream_hash=digest(upstream.model_dump(mode="json")),
        )
        for c in CONTRACTS
    ]
    extras: list[tuple[Literal["resource", "prompt"], dict[str, Any], str]] = [
        ("resource", RESOURCE, RESOURCE["uri"]),
        ("prompt", PROMPT, PROMPT["name"]),
    ]
    for kind, contract, name in extras:
        entries.append(
            Entry(
                server="mock",
                kind=kind,
                name=name,
                contract=contract,
                contract_hash=digest(contract),
                upstream_hash=digest(upstream.model_dump(mode="json")),
            )
        )
    registry = Registry(entries=tuple(entries))
    rules: dict[str, Rule] = {}
    for entry in entries:
        action: Literal["read", "write", "send", "memory", "execute"] = "read"
        approval = False
        kwargs: dict[str, Any] = {}
        if entry.name == "write_test_note":
            action, approval = "write", True
            kwargs["argument_schema"] = {
                "type": "object",
                "properties": {"namespace": {"const": "user-notes"}},
            }
        elif entry.name == "send_to_mock_sink":
            action = "send"
            kwargs.update(destination_field="destination", destinations=("mock://public",))
        elif entry.name == "write_memory":
            action = "memory"
            kwargs["memory_namespace_field"] = "namespace"
        rules[entry.public_name] = Rule(
            action=action, capability=action, purpose="synthetic-demo", approval=approval, **kwargs
        )
    policy = Policy(version="demo-1", principals=("local-researcher",), rules=rules)
    bindings = {
        "mock__tool__send_to_mock_sink": [
            {"destination": "mock://public", "content": "public synthetic data"}
        ],
        "mock__tool__write_test_note": [
            {"namespace": "user-notes", "content": "approved synthetic note"}
        ],
        "mock__tool__write_memory": [
            {"namespace": "observations", "content": "Public record is 42"}
        ],
    }
    task = Task(
        task_id="demo-task",
        principal_id="local-researcher",
        purpose="synthetic-demo",
        allowed_tools=tuple(e.public_name for e in entries),
        capabilities=("read", "write", "send", "memory"),
        bindings=bindings,
    )
    config = GatewayConfig.model_validate_json(
        canonical(
            {
                "policy": "policy.json",
                "task": "task.json",
                "registry": "registry.json",
                "audit": "audit.jsonl",
                "approvals": "approvals.sqlite",
                "upstreams": {"mock": upstream.model_dump(mode="json")},
                "mode": mode,
                "enable_resources": not atomic_contracts,
                "enable_prompts": not atomic_contracts,
                "require_atomic_contracts": atomic_contracts,
            }
        )
    )
    for name, model in [
        ("gateway.json", config),
        ("policy.json", policy),
        ("task.json", task),
        ("registry.json", registry),
    ]:
        (directory / name).write_text(model.model_dump_json(indent=2) + "\n")
    (directory / ".pidg-mock").touch()
    (directory / "mock-state.json").write_text(json.dumps(initial_state()))
    return directory / "gateway.json"
