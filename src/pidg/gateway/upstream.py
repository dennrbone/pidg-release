from __future__ import annotations

import os
from contextlib import AsyncExitStack
from datetime import timedelta
from typing import Any

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from pydantic import Field

from pidg.audit.logging import protect_mcp_logs
from pidg.core.models import StrictModel, UpstreamConfig
from pidg.gateway.registry import Entry


class ContractRejected(Exception):
    """A cooperating trusted executor rejected the pin before its handler ran."""


class ContractReceipt(StrictModel):
    hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    version: int = Field(ge=1)
    executed: bool


class Upstreams:
    def __init__(self, configs: dict[str, UpstreamConfig], timeout: float) -> None:
        protect_mcp_logs()
        self.configs = configs
        self.timeout = timeout
        self.sessions: dict[str, ClientSession] = {}
        self.stack = AsyncExitStack()
        self.atomic_servers: set[str] = set()
        self.read_snapshot_servers: set[str] = set()

    async def __aenter__(self) -> Upstreams:
        self.sessions.clear()
        self.atomic_servers.clear()
        self.read_snapshot_servers.clear()
        try:
            for name, config in self.configs.items():
                # Raw child stderr can contain credentials even when MCP results are redacted.
                errlog = self.stack.enter_context(open(os.devnull, "w"))
                streams = await self.stack.enter_async_context(
                    stdio_client(
                        StdioServerParameters(
                            command=config.command, args=list(config.args), cwd=config.cwd, env={}
                        ),
                        errlog=errlog,
                    )
                )
                session = await self.stack.enter_async_context(
                    ClientSession(
                        streams[0], streams[1], read_timeout_seconds=timedelta(seconds=self.timeout)
                    )
                )
                initialized = await session.initialize()
                experimental = initialized.capabilities.experimental or {}
                if experimental.get("pidg/atomic-contracts") == {"version": 1}:
                    self.atomic_servers.add(name)
                    if experimental.get("pidg/reviewed-read") == {"version": 1}:
                        self.read_snapshot_servers.add(name)
                self.sessions[name] = session
        except BaseException:
            await self.stack.aclose()
            raise
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.stack.aclose()

    async def catalog(self, server: str, kind: str) -> list[dict[str, Any]]:
        session = self.sessions[server]
        items: list[dict[str, Any]] = []
        cursor = None
        seen: set[str] = set()
        with anyio.fail_after(self.timeout):
            for _ in range(100):
                if kind == "tool":
                    result = await session.list_tools(cursor=cursor)
                    batch = result.tools
                elif kind == "resource":
                    resources = await session.list_resources(cursor=cursor)
                    batch = resources.resources  # type: ignore[assignment]
                    result = resources  # type: ignore[assignment]
                else:
                    prompts = await session.list_prompts(cursor=cursor)
                    batch = prompts.prompts  # type: ignore[assignment]
                    result = prompts  # type: ignore[assignment]
                items.extend(
                    item.model_dump(mode="json", by_alias=True, exclude_none=True) for item in batch
                )
                cursor = result.nextCursor
                if not cursor:
                    break
                if cursor in seen:
                    raise ValueError("pagination loop")
                seen.add(cursor)
            else:
                raise ValueError("catalog too large")
        key = "uri" if kind == "resource" else "name"
        names = [item[key] for item in items]
        if len(names) != len(set(names)):
            raise ValueError("ambiguous upstream catalog")
        return items

    async def call(self, server: str, kind: str, name: str, args: dict[str, Any]) -> dict[str, Any]:
        session = self.sessions[server]
        with anyio.fail_after(self.timeout):
            if kind == "tool":
                result = await session.call_tool(name, args)
            elif kind == "resource":
                result = await session.read_resource(name)  # type: ignore[assignment,arg-type]
            else:
                result = await session.get_prompt(name, arguments=args)  # type: ignore[assignment]
            return result.model_dump(mode="json", by_alias=True, exclude_none=True)

    async def call_pinned(
        self, entry: Entry, args: dict[str, Any], *, reviewed_read: bool = False
    ) -> dict[str, Any]:
        if entry.kind != "tool" or entry.server not in self.atomic_servers:
            raise ValueError("atomic executor unavailable")
        if reviewed_read and entry.server not in self.read_snapshot_servers:
            raise ValueError("reviewed read executor unavailable")
        key = "pidg/reviewed-read" if reviewed_read else "pidg/contract"
        pin = {"hash": entry.contract_hash, "version": entry.contract_version}
        with anyio.fail_after(self.timeout):
            response = await self.sessions[entry.server].call_tool(
                entry.name, args, meta={key: pin}
            )
        result = response.model_dump(mode="json", by_alias=True, exclude_none=True)
        receipt = ContractReceipt.model_validate(result.get("_meta", {}).get(key, {}))
        if receipt.executed is False and result.get("isError"):
            raise ContractRejected
        if receipt.model_dump() != {**pin, "executed": True}:
            raise ValueError("atomic execution receipt missing or mismatched")
        return result
