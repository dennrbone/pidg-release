from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

import anyio
from jsonschema import ValidationError
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.server.stdio import stdio_server
from pydantic import AnyUrl

from pidg.audit.storage import AuditLog
from pidg.core.authorization import ApprovalStore
from pidg.core.models import Decision, GatewayConfig, Policy, Task, canonical, digest
from pidg.core.policy import PolicyEngine, validate_schema
from pidg.core.provenance import ProvenanceTracker
from pidg.gateway.protocol import load_config
from pidg.gateway.registry import Entry, Registry, execution_contract
from pidg.gateway.upstream import ContractRejected, Upstreams
from pidg.guards.egress_guard import EgressGuard
from pidg.guards.input_guard import InputGuard, secret_labels
from pidg.guards.memory_guard import MemoryGuard


class Gateway:
    def __init__(
        self,
        config: GatewayConfig,
        policy: Policy,
        task: Task,
        registry: Registry,
        upstreams: Upstreams,
        base: Path,
        *,
        input_guard: InputGuard | None = None,
    ) -> None:
        self.config = config.model_copy(deep=True)
        self.task = task.model_copy(deep=True)
        self.registry = registry.model_copy(deep=True)
        self.engine = PolicyEngine(policy.model_copy(deep=True))
        self.upstreams = upstreams
        self.audit = AuditLog(base / config.audit)
        self.approvals = ApprovalStore(base / config.approvals)
        self.tracker = ProvenanceTracker()
        self.input_guard = input_guard or InputGuard(protected_values=config.protected_values)
        self.run_id = uuid4().hex
        self.lock = anyio.Lock()
        self.delivered_sources: list[str] = []
        self.observed_contracts: set[str] = set()

    def event(
        self,
        name: str,
        args: dict[str, Any],
        decision: Decision,
        reason: str,
        execution: bool | None,
        status: str,
        start: float,
        **extra: Any,
    ) -> dict[str, Any]:
        entry = self.registry.get(name)
        return {
            "run_id": self.run_id,
            "task_id": self.task.task_id,
            "principal_id": self.task.principal_id,
            "tool_name": name if self.registry.get(name) else "<unknown>",
            "contract_hash": entry.contract_hash if entry else None,
            "contract_version": entry.contract_version if entry else None,
            "source_ids": list(self.delivered_sources),
            "policy_version": self.engine.policy.version if self.engine.policy else "missing",
            "decision": decision.value,
            "reason_code": reason,
            "attempted_action": digest(args),
            "actual_execution": execution,
            "result_status": status,
            "latency_ms": round((time.perf_counter() - start) * 1000, 3),
            **extra,
        }

    async def invoke(
        self, name: str, arguments: dict[str, Any], *, kind: str | None = None
    ) -> dict[str, Any]:
        async with self.lock:
            return await self._invoke(name, arguments, kind)

    def reviewed_read(self, entry: Entry, current: dict[str, Any]) -> bool:
        rule = self.engine.policy.rules.get(entry.public_name) if self.engine.policy else None
        return bool(
            self.config.reviewed_read_fallback
            and self.config.require_atomic_contracts
            and entry.kind == "tool"
            and rule
            and rule.action == "read"
            and entry.server in self.upstreams.atomic_servers
            and entry.server in self.upstreams.read_snapshot_servers
            and digest(execution_contract(current)) == digest(execution_contract(entry.contract))
        )

    async def _invoke(
        self, name: str, arguments: dict[str, Any], kind: str | None = None
    ) -> dict[str, Any]:
        start = time.perf_counter()
        args: dict[str, Any] = {}
        dispatched = False
        audit_started = False
        decision, reason = Decision.DENY, "INTERNAL_FAILURE"
        action_hash: str | None = None
        try:
            encoded = canonical(arguments)
            if len(encoded) > 1_000_000:
                raise ValueError("arguments too large")
            args = json.loads(encoded)
            entry = self.registry.get(name)
            if entry is None:
                return self._deny(name, args, "UNKNOWN_TOOL", start)
            if kind is not None and entry.kind != kind:
                return self._deny(name, args, "PROTOCOL_KIND_MISMATCH", start)
            if entry.kind == "resource" and not self.config.enable_resources:
                return self._deny(name, args, "RESOURCE_DISABLED", start)
            if entry.kind == "prompt" and not self.config.enable_prompts:
                return self._deny(name, args, "PROMPT_DISABLED", start)
            if (
                digest(self.config.upstreams[entry.server].model_dump(mode="json"))
                != entry.upstream_hash
            ):
                return self._deny(name, args, "UPSTREAM_IDENTITY_CHANGED", start)
            catalog = await self.upstreams.catalog(entry.server, entry.kind)
            key = "uri" if entry.kind == "resource" else "name"
            current = next((item for item in catalog if item[key] == entry.name), None)
            if current is None:
                return self._deny(name, args, "TOOL_DISAPPEARED", start)
            contract_reason = None
            use_reviewed_read = False
            if digest(current) != entry.contract_hash:
                use_reviewed_read = self.reviewed_read(entry, current)
                contract_reason = (
                    "CONTRACT_CHANGED_REPIN_REQUIRED"
                    if self.engine.policy and self.engine.policy.contract_changes == "require_repin"
                    else "CONTRACT_CHANGED"
                )
                if use_reviewed_read:
                    contract_reason = None
                elif self.config.mode != "monitor":
                    return self._deny(name, args, contract_reason, start)
            displayed = entry.contract
            if digest(displayed) not in self.observed_contracts:
                description_scan = self.input_guard.scan(canonical(displayed), "tool_description")
                source = self.tracker.external(
                    displayed, "tool_description", entry.public_name, description_scan.labels
                )
                self.delivered_sources.append(source.source_id)
                self.observed_contracts.add(digest(displayed))
            schema = self.argument_schema(entry)
            try:
                validate_schema(schema, args)
            except (ValidationError, ValueError):
                return self._deny(name, args, "INVALID_ARGUMENTS", start)
            scan = self.input_guard.scan(encoded, "tool_arguments")
            bound = any(
                canonical(args) == canonical(binding)
                for binding in self.task.bindings.get(name, [])
            )
            bound_scope = bound and self.config.scope_labels_to_bound_arguments
            # Only the operator's exact precommitted bytes can exclude ambient context taint.
            labels = (self.tracker.labels if not bound_scope else frozenset()) | {"unverified"}
            labels |= secret_labels(encoded, protected_values=self.config.protected_values)
            verdict = self.engine.authorize(self.task, name, args, labels, bound)
            decision, reason = verdict.decision, verdict.reason_code
            rule = self.engine.policy.rules.get(name) if self.engine.policy else None
            if decision != Decision.DENY and rule:
                guard_reason = EgressGuard().check(
                    rule, args, labels, protected_values=self.config.protected_values
                )
                if not guard_reason:
                    guard_reason = MemoryGuard().check(rule, args)
                if guard_reason:
                    decision, reason = Decision.DENY, guard_reason
            if self.config.mode == "strict" and rule and rule.action != "read" and not bound:
                decision, reason = Decision.DENY, "STRICT_REQUIRES_TRUSTED_BINDING"
            if decision == Decision.REQUIRE_APPROVAL:
                descriptor = {
                    "run_id": self.run_id,
                    "principal_id": self.task.principal_id,
                    "task_hash": digest(self.task.model_dump(mode="json")),
                    "tool": name,
                    "arguments_hash": digest(args),
                    "policy_hash": digest(self.engine.policy.model_dump(mode="json"))
                    if self.engine.policy
                    else "missing",
                    "contract_hash": entry.contract_hash,
                    "contract_version": entry.contract_version,
                    "sources": sorted(self.delivered_sources),
                }
                action_hash = digest(descriptor)
                self.approvals.request(action_hash, review=descriptor)
                if self.approvals.consume(action_hash):
                    decision, reason = Decision.ALLOW, "APPROVAL_CONSUMED"
            if contract_reason:
                decision, reason = Decision.DENY, contract_reason
            would_decision = decision.value
            if self.config.mode == "monitor":
                decision, reason = Decision.ALLOW, "MONITOR_WOULD_" + reason
            if decision != Decision.ALLOW:
                event = self.event(
                    name,
                    args,
                    decision,
                    reason,
                    False,
                    "blocked",
                    start,
                    action_hash=action_hash,
                    detector_findings=list(scan.findings),
                )
                self.audit.append(event)
                return self.result_error(reason, decision, action_hash)
            if self.config.require_atomic_contracts and (
                entry.kind != "tool" or entry.server not in self.upstreams.atomic_servers
            ):
                return self._deny(name, args, "ATOMIC_EXECUTOR_UNAVAILABLE", start)
            latest = await self.upstreams.catalog(entry.server, entry.kind)
            last = next((item for item in latest if item[key] == entry.name), None)
            if last is None or digest(last) != entry.contract_hash:
                if last is not None and self.reviewed_read(entry, last):
                    use_reviewed_read = True
                else:
                    return self._deny(name, args, "CONTRACT_CHANGED_BEFORE_DISPATCH", start)
            event = self.event(
                name,
                args,
                decision,
                reason,
                False,
                "dispatch_intent",
                start,
                would_decision=would_decision,
                detector_findings=list(scan.findings),
                argument_label_scope="operator_bound" if bound_scope else "session",
                reviewed_read_snapshot=use_reviewed_read,
            )
            self.audit.append(event)
            audit_started = True
            dispatched = True
            # Use a fresh copy; callers cannot change the checked snapshot during await.
            # Only the cooperating executor can compare and execute atomically; legacy MCP cannot.
            result = (
                await self.upstreams.call_pinned(entry, json.loads(encoded), reviewed_read=True)
                if use_reviewed_read
                else await self.upstreams.call_pinned(entry, json.loads(encoded))
                if self.config.require_atomic_contracts
                else await self.upstreams.call(
                    entry.server, entry.kind, entry.name, json.loads(encoded)
                )
            )
            payload = canonical(result)
            response_scan = self.input_guard.scan(payload, "tool_result")
            response_labels = response_scan.labels | secret_labels(
                payload, protected_values=self.config.protected_values
            )
            source = self.tracker.external(
                result, "tool_result", entry.public_name, response_labels
            )
            self.delivered_sources.append(source.source_id)
            withheld_reason = (
                "SENSITIVE_OR_OVERSIZED_RESULT_WITHHELD"
                if len(payload) > 1_000_000 or response_labels
                else None
            )
            result_status = (
                "result_withheld"
                if withheld_reason
                else "upstream_error"
                if result.get("isError")
                else "completed"
            )
            self.audit.append(
                self.event(
                    name,
                    args,
                    Decision.DENY if withheld_reason else decision,
                    withheld_reason or reason,
                    True,
                    result_status,
                    start,
                    detector_findings=list(response_scan.findings),
                    result_hash=digest(result),
                    source_metadata=source.public_metadata(),
                )
            )
            if withheld_reason:
                return self.result_error(withheld_reason)
            authorization = {
                "decision": decision.value,
                "reason_code": reason,
                "policy_version": self.engine.policy.version if self.engine.policy else "missing",
                "run_id": self.run_id,
                "task_id": self.task.task_id,
            }
            if entry.kind != "tool":
                return {
                    "payload": result,
                    "source": source.public_metadata(),
                    "risk": response_scan.risk,
                    "authorization": authorization,
                }
            # Wrapping prevents a server-supplied _meta from impersonating gateway evidence.
            return {
                "content": [
                    types.TextContent(
                        type="text",
                        text=canonical(
                            {
                                "authorization": authorization,
                                "untrusted_result": result,
                                "provenance": source.public_metadata(),
                                "input_guard": {
                                    "risk": response_scan.risk,
                                    "findings": response_scan.findings,
                                },
                            }
                        ),
                    ).model_dump(mode="json")
                ],
                "isError": bool(result.get("isError", False)),
            }
        except ContractRejected:
            return self._deny(name, args, "ATOMIC_CONTRACT_REJECTED", start)
        except anyio.get_cancelled_exc_class():
            self.audit.append(
                self.event(
                    name,
                    args,
                    Decision.DENY,
                    "REQUEST_CANCELLED",
                    None if dispatched else False,
                    "execution_unknown" if dispatched else "not_dispatched",
                    start,
                )
            )
            raise
        except Exception:
            # Exception text can contain raw upstream secrets or validation values.
            try:
                self.audit.append(
                    self.event(
                        name,
                        args,
                        Decision.DENY,
                        "DEPENDENCY_FAILURE",
                        None if dispatched else False,
                        "execution_unknown" if dispatched else "not_dispatched",
                        start,
                        had_dispatch_intent=audit_started,
                    )
                )
            except Exception:
                return self.result_error(
                    "AUDIT_UNAVAILABLE_EXECUTION_UNKNOWN" if dispatched else "AUDIT_UNAVAILABLE"
                )
            return self.result_error(
                "DEPENDENCY_FAILURE_EXECUTION_UNKNOWN" if dispatched else "DEPENDENCY_FAILURE"
            )

    def _deny(self, name: str, args: dict[str, Any], reason: str, start: float) -> dict[str, Any]:
        self.audit.append(self.event(name, args, Decision.DENY, reason, False, "blocked", start))
        return self.result_error(reason)

    def result_error(
        self, reason: str, decision: Decision = Decision.DENY, action: str | None = None
    ) -> dict[str, Any]:
        return {
            "isError": True,
            "content": [
                {
                    "type": "text",
                    "text": canonical(
                        {
                            "decision": decision.value,
                            "reason_code": reason,
                            "approval_action": action,
                            "run_id": self.run_id,
                            "task_id": self.task.task_id,
                            "policy_version": self.engine.policy.version
                            if self.engine.policy
                            else "missing",
                        }
                    ),
                }
            ],
        }

    @staticmethod
    def argument_schema(entry: Entry) -> dict[str, Any]:
        if entry.kind == "tool":
            return dict(entry.contract["inputSchema"])
        if entry.kind == "resource":
            return {"type": "object", "additionalProperties": False}
        arguments = entry.contract.get("arguments", [])
        return {
            "type": "object",
            "properties": {arg["name"]: {"type": "string"} for arg in arguments},
            "required": [arg["name"] for arg in arguments if arg.get("required")],
            "additionalProperties": False,
        }

    def make_server(self) -> Server[Any]:
        server: Server[Any] = Server("pidg")

        @server.list_tools()
        async def list_tools() -> list[types.Tool]:
            # Discovery uses reviewed metadata; drift is checked independently before dispatch.
            return [
                types.Tool(
                    name=e.public_name,
                    description=e.contract.get("description", ""),
                    inputSchema=self.argument_schema(e),
                )
                for e in self.registry.entries
                if e.kind == "tool" and e.public_name in self.task.allowed_tools
            ]

        @server.call_tool(validate_input=False)
        async def call_tool(name: str, arguments: dict[str, Any]) -> types.CallToolResult:
            return types.CallToolResult.model_validate(
                await self.invoke(name, arguments, kind="tool")
            )

        if self.config.enable_resources:

            @server.list_resources()
            async def list_resources() -> list[types.Resource]:
                return [
                    types.Resource(
                        uri=AnyUrl(e.public_name), name=e.contract.get("name", "resource")
                    )
                    for e in self.registry.entries
                    if e.kind == "resource" and e.public_name in self.task.allowed_tools
                ]

            @server.read_resource()
            async def read_resource(uri: AnyUrl) -> list[ReadResourceContents]:
                result = await self.invoke(str(uri), {}, kind="resource")
                if result.get("isError"):
                    raise ValueError("PIDG resource denied")
                return [
                    ReadResourceContents(content=canonical(result), mime_type="application/json")
                ]

        if self.config.enable_prompts:

            @server.list_prompts()
            async def list_prompts() -> list[types.Prompt]:
                return [
                    types.Prompt(name=e.public_name, arguments=e.contract.get("arguments"))
                    for e in self.registry.entries
                    if e.kind == "prompt" and e.public_name in self.task.allowed_tools
                ]

            @server.get_prompt()
            async def get_prompt(
                name: str, arguments: dict[str, str] | None
            ) -> types.GetPromptResult:
                result = await self.invoke(name, arguments or {}, kind="prompt")
                if result.get("isError"):
                    raise ValueError("PIDG prompt denied")
                # A prompt from upstream remains untrusted user content, never a system instruction.
                return types.GetPromptResult(
                    messages=[
                        types.PromptMessage(
                            role="user",
                            content=types.TextContent(type="text", text=canonical(result)),
                        )
                    ]
                )

        return server


async def serve(path: Path) -> None:
    config, policy, task, registry = load_config(path)
    async with Upstreams(config.upstreams, config.timeout_seconds) as upstreams:
        gateway = Gateway(config, policy, task, registry, upstreams, path.resolve().parent)
        server = gateway.make_server()
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())
