from __future__ import annotations

import argparse
import importlib.metadata
import json
import platform
import shutil
import sys
from pathlib import Path
from typing import Any

import anyio

from pidg.adapters.configuration import apply, audit_config, generate, parse_jsonc, plan, rollback
from pidg.core.authorization import ApprovalStore
from pidg.core.models import canonical, digest, parse_json
from pidg.gateway.protocol import load_config, read_model
from pidg.gateway.registry import Entry, Registry
from pidg.gateway.server import serve
from pidg.gateway.upstream import Upstreams
from pidg.guards.input_guard import InputGuard
from pidg.research.fixtures import create_demo


def print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False))


def doctor() -> dict[str, Any]:
    versions = {
        name: importlib.metadata.version(name) for name in ("pidg", "mcp", "pydantic", "jsonschema")
    }
    extensions = list((Path.home() / ".vscode/extensions").glob("*gigacode*/package.json"))
    return {
        "python": platform.python_version(),
        "platform": platform.system(),
        "versions": versions,
        "gigacode_cli": shutil.which("gigacode")
        or next(
            (
                str(p.parent / "bin/gigacode")
                for p in extensions
                if (p.parent / "bin/gigacode").is_file()
            ),
            None,
        ),
        "vscode_extensions": [
            {"path": str(p.parent), "version": json.loads(p.read_text()).get("version")}
            for p in extensions
        ],
        "transport": "stdio",
        "global_settings_changed": False,
        "builtin_interception": "unverified; sandbox required",
        "network_proxy": False,
    }


async def snapshot(path: Path) -> Registry:
    config, _, _, _ = load_config(path)
    entries = []
    async with Upstreams(config.upstreams, config.timeout_seconds) as upstreams:
        for server, upstream in config.upstreams.items():
            for kind in (
                ["tool"]
                + (["resource"] if config.enable_resources else [])
                + (["prompt"] if config.enable_prompts else [])
            ):
                for contract in await upstreams.catalog(server, kind):
                    name = contract["uri"] if kind == "resource" else contract["name"]
                    entries.append(
                        Entry.model_validate_json(
                            canonical(
                                {
                                    "server": server,
                                    "kind": kind,
                                    "name": name,
                                    "contract": contract,
                                    "contract_hash": digest(contract),
                                    "upstream_hash": digest(upstream.model_dump(mode="json")),
                                    "contract_version": contract.get("_meta", {}).get(
                                        "pidg/contractVersion", 1
                                    ),
                                }
                            )
                        )
                    )
    return Registry(entries=tuple(entries))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="pidg")
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor")
    init = commands.add_parser("init")
    init.add_argument("--directory", type=Path, default=Path(".pidg"))
    init.add_argument("--atomic-contracts", action="store_true")
    server = commands.add_parser("serve")
    server.add_argument("--config", type=Path, required=True)
    scan = commands.add_parser("scan")
    scan.add_argument("path", type=Path)
    scan.add_argument("--context", default="document")
    config = commands.add_parser("config").add_subparsers(dest="operation", required=True)
    validate = config.add_parser("validate")
    validate.add_argument("path", type=Path)
    for command in ("generate", "plan", "apply"):
        sub = config.add_parser(command)
        sub.add_argument(
            "--target",
            choices=("gigacode-cli", "gigacode-vscode", "gigacode-bundled"),
            required=True,
        )
        sub.add_argument("--gateway", type=Path, required=True)
        if command != "generate":
            sub.add_argument("--path", type=Path, required=True)
        if command == "apply":
            sub.add_argument("--yes", action="store_true")
    audit = config.add_parser("audit")
    audit.add_argument("paths", type=Path, nargs="+")
    audit.add_argument(
        "--target",
        choices=("gigacode-cli", "gigacode-vscode", "gigacode-bundled"),
        default="gigacode-cli",
    )
    revert = config.add_parser("rollback")
    revert.add_argument("--path", type=Path, required=True)
    revert.add_argument("--yes", action="store_true")
    audit_export = (
        commands.add_parser("audit")
        .add_subparsers(dest="operation", required=True)
        .add_parser("export")
    )
    audit_export.add_argument("--path", type=Path, required=True)
    approval = commands.add_parser("approval").add_subparsers(dest="operation", required=True)
    for command in ("pending", "inspect", "grant"):
        sub = approval.add_parser(command)
        sub.add_argument("--store", type=Path, required=True)
        if command in {"inspect", "grant"}:
            sub.add_argument("action")
        if command == "grant":
            sub.add_argument("--arguments", type=Path, required=True)
            sub.add_argument("--yes", action="store_true")
    registry = commands.add_parser("registry").add_subparsers(dest="operation", required=True)
    for command in ("snapshot", "pin"):
        sub = registry.add_parser(command)
        sub.add_argument("--config", type=Path, required=True)
        if command == "pin":
            sub.add_argument("--candidate", type=Path, required=True)
            sub.add_argument("--yes", action="store_true")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "doctor":
            print_json(doctor())
        elif args.command == "init":
            print(create_demo(args.directory, atomic_contracts=args.atomic_contracts))
        elif args.command == "serve":
            anyio.run(serve, args.config)
        elif args.command == "scan":
            scan = InputGuard().scan(args.path.read_text(), args.context)
            print_json(
                {
                    "risk": scan.risk,
                    "findings": scan.findings,
                    "labels": sorted(scan.labels),
                    "authorization": "not granted by text analysis",
                }
            )
        elif args.command == "config":
            if args.operation == "validate":
                load_config(args.path)
                print_json({"valid": True})
            elif args.operation == "audit":
                findings = {
                    str(path): audit_config(parse_jsonc(path.read_text()), args.target)
                    for path in args.paths
                }
                print_json(findings)
                return int(any(findings.values()))
            elif args.operation == "rollback":
                if not args.yes:
                    raise ValueError("rollback requires explicit --yes")
                rollback(args.path)
            else:
                generated = generate(args.target, args.gateway)
                if args.operation == "generate":
                    print_json(generated)
                else:
                    updated, diff = plan(args.path, generated)
                    print(diff)
                    if args.operation == "apply":
                        if not args.yes:
                            raise ValueError("review diff; apply requires explicit --yes")
                        apply(args.path, updated)
        elif args.command == "audit":
            from pidg.audit.storage import AuditLog

            for event in AuditLog(args.path).events():
                print(canonical(event))
        elif args.command == "approval":
            store = ApprovalStore(args.store)
            if args.operation == "pending":
                print_json(store.pending())
            elif args.operation == "inspect":
                print_json(store.review(args.action))
            else:
                if not args.yes:
                    raise ValueError(
                        "review exact action/arguments in trusted operator UI; --yes required"
                    )
                arguments = parse_json(args.arguments.read_text())
                if not isinstance(arguments, dict):
                    raise ValueError("arguments must be an object")
                print_json(store.review(args.action))
                store.grant(args.action, arguments)
        elif args.command == "registry":
            if args.operation == "snapshot":
                print_json(anyio.run(snapshot, args.config).model_dump(mode="json"))
            else:
                config, _, _, _ = load_config(args.config)
                candidate = read_model(args.candidate, Registry)
                destination = args.config.resolve().parent / config.registry
                data = candidate.model_dump(mode="json")
                updated, diff = plan(destination, data)
                print(diff)
                if not args.yes:
                    raise ValueError("repinning requires reviewed candidate and --yes")
                apply(destination, updated)
        return 0
    except Exception as error:
        # Avoid echoing config/validation/upstream values that can include secrets.
        print(
            f"PIDG failed closed ({type(error).__name__}); inspect local configuration and doctor.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
