from __future__ import annotations

import difflib
import json
import os
import sys
from pathlib import Path
from typing import Any

from pidg.core.models import parse_json
from pidg.gateway.protocol import load_config


def strip_jsonc(text: str) -> str:
    """Replace comments/trailing commas with spaces, preserving string content and offsets."""
    chars = list(text)
    i = 0
    in_string = False
    while i < len(chars):
        if in_string:
            if chars[i] == "\\":
                i += 2
                continue
            if chars[i] == '"':
                in_string = False
        elif chars[i] == '"':
            in_string = True
        elif text[i : i + 2] == "//":
            end = text.find("\n", i)
            end = len(text) if end < 0 else end
            chars[i:end] = " " * (end - i)
            i = end
            continue
        elif text[i : i + 2] == "/*":
            end = text.find("*/", i + 2)
            if end < 0:
                raise ValueError("unterminated JSONC comment")
            for j in range(i, end + 2):
                if chars[j] != "\n":
                    chars[j] = " "
            i = end + 2
            continue
        i += 1
    in_string = False
    i = 0
    while i < len(chars):
        if in_string:
            if chars[i] == "\\":
                i += 2
                continue
            if chars[i] == '"':
                in_string = False
        elif chars[i] == '"':
            in_string = True
        elif chars[i] == ",":
            j = i + 1
            while j < len(chars) and chars[j].isspace():
                j += 1
            if j < len(chars) and chars[j] in "}]":
                chars[i] = " "
        i += 1
    return "".join(chars)


def parse_jsonc(text: str) -> dict[str, Any]:
    result = parse_json(strip_jsonc(text))
    if not isinstance(result, dict):
        raise ValueError("config must be object")
    return result


def generate(target: str, gateway_path: Path) -> dict[str, Any]:
    config, _, task, registry = load_config(gateway_path)
    entry: dict[str, Any] = {
        "command": sys.executable,
        "args": ["-I", "-m", "pidg.cli", "serve", "--config", str(gateway_path.resolve())],
        "cwd": str(gateway_path.resolve().parent),
        "env": {},
    }
    if target == "gigacode-cli":
        entry.update(
            trust=False,
            includeTools=[
                e.public_name
                for e in registry.entries
                if e.kind == "tool" and e.public_name in task.allowed_tools
            ],
            excludeTools=[],
        )
        return {
            "mcpServers": {"pidg": entry},
            "mcp": {"allowed": ["pidg"], "excluded": sorted(config.upstreams)},
        }
    if target == "gigacode-vscode":
        return {"mcpServers": {"pidg": entry}}
    if target == "gigacode-bundled":
        return {
            "mcp": {
                "pidg": {
                    "type": "local",
                    "command": [entry["command"], *entry["args"]],
                    "enabled": True,
                }
            }
        }
    raise ValueError("unknown target")


def audit_config(data: dict[str, Any], target: str) -> list[str]:
    if target == "gigacode-bundled":
        servers = data.get("mcp", {})
        if not isinstance(servers, dict):
            return ["INVALID_MCP_SERVERS"]
        findings = ["DIRECT_MCP_BYPASS:" + name for name in servers if name != "pidg"]
        if data.get("mcpServers"):
            findings.append("LEGACY_CONNECTIONS_REQUIRE_REVIEW")
        entry = servers.get("pidg", {})
        command = entry.get("command", []) if isinstance(entry, dict) else []
        if (
            not isinstance(command, list)
            or len(command) != 7
            or not isinstance(command[0], str)
            or Path(command[0]).resolve() != Path(sys.executable).resolve()
            or command[1:6] != ["-I", "-m", "pidg.cli", "serve", "--config"]
            or entry.get("type") != "local"
            or entry.get("enabled") is not True
            or set(entry) != {"type", "command", "enabled"}
        ):
            findings.append("GATEWAY_COMMAND_UNVERIFIED")
        return findings
    findings = []
    servers = data.get("mcpServers", {})
    if not isinstance(servers, dict):
        return ["INVALID_MCP_SERVERS"]
    if "pidg" not in servers:
        findings.append("GATEWAY_MISSING")
    for name, server in servers.items():
        if name != "pidg":
            findings.append("DIRECT_MCP_BYPASS:" + name)
        elif (
            not isinstance(server, dict)
            or server.get("args", [])[:5] != ["-I", "-m", "pidg.cli", "serve", "--config"]
            or not isinstance(server.get("command"), str)
            or Path(server["command"]).resolve() != Path(sys.executable).resolve()
        ):
            findings.append("GATEWAY_COMMAND_UNVERIFIED")
        elif server.get("httpUrl") or server.get("url"):
            findings.append("ALTERNATE_GATEWAY_TRANSPORT")
        elif len(server.get("args", [])) != 6 or server.get("env", {}) != {}:
            findings.append("UNREVIEWED_GATEWAY_LAUNCH")
        elif target == "gigacode-cli" and server.get("trust") is not False:
            findings.append("CONFIRMATIONS_NOT_PRESERVED")
    if target == "gigacode-cli" and data.get("mcp", {}).get("allowed") != ["pidg"]:
        findings.append("SERVER_ALLOWLIST_MISSING")
    return findings


def patch_jsonc(original: str, changes: dict[str, Any]) -> str:
    """Replace top-level values only; preserve unrelated JSONC and comments."""
    parse_jsonc(original)
    stripped = strip_jsonc(original)
    decoder = json.JSONDecoder()
    position = stripped.index("{") + 1
    spans: dict[str, tuple[int, int]] = {}
    while True:
        while stripped[position].isspace() or stripped[position] == ",":
            position += 1
        if stripped[position] == "}":
            break
        key, end = decoder.raw_decode(stripped, position)
        position = end
        while stripped[position].isspace() or stripped[position] == ":":
            position += 1
        _, end = decoder.raw_decode(stripped, position)
        spans[key] = (position, end)
        position = end
    result = original
    replacements = [
        (spans[k][0], spans[k][1], json.dumps(v, indent=2))
        for k, v in changes.items()
        if k in spans
    ]
    for start, end, value in sorted(replacements, reverse=True):
        result = result[:start] + value + result[end:]
    missing = {k: v for k, v in changes.items() if k not in spans}
    if missing:
        opening = result.index("{") + 1
        insertion = json.dumps(missing, indent=2)[1:-1].strip()
        result = (
            result[:opening] + "\n" + insertion + ("," if spans else "") + "\n" + result[opening:]
        )
    parse_jsonc(result)
    return result


def plan(path: Path, changes: dict[str, Any]) -> tuple[str, str]:
    if path.is_symlink():
        raise ValueError("symlink config denied")
    original = path.read_text() if path.exists() else "{}\n"
    existing = parse_jsonc(original)
    changes = dict(changes)
    if "mcpServers" in changes:
        servers = existing.get("mcpServers", {})
        if not isinstance(servers, dict):
            raise ValueError("invalid existing MCP server map")
        changes["mcpServers"] = {**servers, **changes["mcpServers"]}
    if isinstance(changes.get("mcp", {}).get("pidg"), dict):
        servers = existing.get("mcp", {})
        if not isinstance(servers, dict):
            raise ValueError("invalid existing MCP map")
        changes["mcp"] = {**servers, **changes["mcp"]}
    updated = patch_jsonc(original, changes)
    diff = "".join(
        difflib.unified_diff(
            original.splitlines(True),
            updated.splitlines(True),
            fromfile=str(path),
            tofile=str(path) + " (PIDG)",
        )
    )
    return updated, diff


def apply(path: Path, updated: str) -> None:
    parse_jsonc(updated)
    path.parent.mkdir(parents=True, exist_ok=True)
    backup = path.with_suffix(path.suffix + ".pidg-backup")
    if backup.exists() or backup.is_symlink():
        raise ValueError("backup already exists; rollback or archive it first")
    if path.is_symlink():
        raise ValueError("symlink config denied")
    fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(path.read_text() if path.exists() else "{}\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary = path.with_suffix(path.suffix + ".pidg-tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(updated)
    temporary.replace(path)


def rollback(path: Path) -> None:
    backup = path.with_suffix(path.suffix + ".pidg-backup")
    if path.is_symlink() or backup.is_symlink():
        raise ValueError("symlink denied")
    if not backup.is_file():
        raise ValueError("no backup")
    backup.replace(path)
