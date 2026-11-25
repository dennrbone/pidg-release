"""Synthetic-only MCP server. No network clients, shell, arbitrary paths or real credentials."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import anyio
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.server.stdio import stdio_server
from pydantic import AnyUrl

from pidg.core.models import canonical, digest
from pidg.core.policy import validate_schema

STATE = Path("mock-state.json")


def schema(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


STRING = {"type": "string", "maxLength": 10000}
CONTRACTS: list[dict[str, Any]] = [
    {
        "name": "read_public_doc",
        "description": "Read a synthetic public document.",
        "inputSchema": schema({"doc_id": STRING}, ["doc_id"]),
    },
    {
        "name": "lookup_test_record",
        "description": "Look up a synthetic record.",
        "inputSchema": schema({"record_id": STRING}, ["record_id"]),
    },
    {
        "name": "write_test_note",
        "description": "Write a synthetic note in a mock namespace.",
        "inputSchema": schema({"namespace": STRING, "content": STRING}, ["namespace", "content"]),
    },
    {
        "name": "send_to_mock_sink",
        "description": "Append synthetic data to a local mock sink; no network.",
        "inputSchema": schema(
            {"destination": STRING, "content": STRING}, ["destination", "content"]
        ),
    },
    {
        "name": "write_memory",
        "description": "Write observations to synthetic memory.",
        "inputSchema": schema({"namespace": STRING, "content": STRING}, ["namespace", "content"]),
    },
]
RESOURCE: dict[str, Any] = {
    "uri": "mock://public/document",
    "name": "public-document",
    "description": "Synthetic resource",
}
PROMPT: dict[str, Any] = {
    "name": "summarize",
    "description": "Synthetic user prompt",
    "arguments": [{"name": "topic", "required": True}],
}


def initial_state() -> dict[str, Any]:
    return {
        "notes": [],
        "sink": [],
        "memory": [],
        "calls": [],
        "document": "Public record: revenue is 42 synthetic units.",
    }


def read_state() -> dict[str, Any]:
    return json.loads(STATE.read_text()) if STATE.exists() else initial_state()


def save_state(state: dict[str, Any]) -> None:
    temporary = STATE.with_suffix(".tmp")
    temporary.write_text(canonical(state))
    temporary.replace(STATE)


async def main() -> None:
    if not Path(".pidg-mock").is_file():
        raise RuntimeError("mock server requires isolated directory with .pidg-mock marker")
    server: Server[Any] = Server("pidg-synthetic-mock")
    execution_lock = anyio.Lock()

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [types.Tool.model_validate(c) for c in CONTRACTS]

    @server.call_tool(validate_input=False)
    async def call_tool(name: str, arguments: dict[str, Any]) -> types.CallToolResult:
        async with execution_lock:
            state = read_state()
            contract = next(c for c in CONTRACTS if c["name"] == name)
            pin = {"hash": digest(contract), "version": 1}
            meta = server.request_context.meta
            requested = meta.model_dump().get("pidg/contract") if meta else None
            receipt_key = "pidg/contract"
            reviewed = meta.model_dump().get("pidg/reviewed-read") if meta else None
            if reviewed is not None:
                if (
                    requested is not None
                    or name not in {"read_public_doc", "lookup_test_record"}
                    or reviewed != pin
                ):
                    return types.CallToolResult(
                        isError=True,
                        content=[types.TextContent(type="text", text="Reviewed read rejected")],
                        _meta={"pidg/reviewed-read": {**pin, "executed": False}},
                    )
                requested, receipt_key = reviewed, "pidg/reviewed-read"
            if requested is not None and requested != pin:
                return types.CallToolResult(
                    isError=True,
                    content=[types.TextContent(type="text", text="Pinned contract rejected")],
                    _meta={"pidg/contract": {**pin, "executed": False}},
                )
            # The trusted handler has no await between comparing this snapshot and applying effects.
            validate_schema(contract["inputSchema"], arguments)
            state["calls"].append(name)
            if name == "read_public_doc":
                output = state["document"]
            elif name == "lookup_test_record":
                output = state.get("records", {}).get(
                    arguments["record_id"], "Public synthetic record 42"
                )
            elif name == "write_test_note":
                state["notes"].append(arguments)
                output = "written"
            elif name == "send_to_mock_sink":
                state["sink"].append(arguments)
                output = "delivered locally"
            elif name == "write_memory":
                state["memory"].append(arguments)
                output = "remembered"
            else:
                raise ValueError("unknown mock tool")
            save_state(state)
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=str(output))],
                _meta={receipt_key: {**pin, "executed": True}} if requested else None,
            )

    @server.list_resources()
    async def resources() -> list[types.Resource]:
        return [types.Resource.model_validate(RESOURCE)]

    @server.read_resource()
    async def resource(uri: AnyUrl) -> list[ReadResourceContents]:
        if str(uri) != RESOURCE["uri"]:
            raise ValueError("unknown resource")
        return [ReadResourceContents(content=str(read_state()["document"]), mime_type="text/plain")]

    @server.list_prompts()
    async def prompts() -> list[types.Prompt]:
        return [types.Prompt.model_validate(PROMPT)]

    @server.get_prompt()
    async def prompt(name: str, arguments: dict[str, str] | None) -> types.GetPromptResult:
        if name != "summarize" or not arguments or set(arguments) != {"topic"}:
            raise ValueError("invalid prompt")
        return types.GetPromptResult(
            messages=[
                types.PromptMessage(
                    role="user",
                    content=types.TextContent(
                        type="text", text="Summarize public synthetic topic: " + arguments["topic"]
                    ),
                )
            ]
        )

    async with stdio_server() as (read, write):
        await server.run(
            read,
            write,
            server.create_initialization_options(
                experimental_capabilities={
                    "pidg/atomic-contracts": {"version": 1},
                    "pidg/reviewed-read": {"version": 1},
                }
            ),
        )


if __name__ == "__main__":
    anyio.run(main)
