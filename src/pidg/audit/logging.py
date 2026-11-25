"""Keep SDK diagnostics useful without forwarding untrusted payloads or exception values."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

_installed: Callable[..., logging.LogRecord] | None = None


def protect_mcp_logs() -> None:
    global _installed
    previous = logging.getLogRecordFactory()
    if previous is _installed:
        return

    def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = previous(*args, **kwargs)
        if record.name == "mcp" or record.name.startswith("mcp."):
            record.msg = "MCP_SDK_DIAGNOSTIC (payload and exception values withheld)"
            record.args = ()
            record.exc_info = None
            record.exc_text = None
            record.stack_info = None
        return record

    _installed = factory
    logging.setLogRecordFactory(factory)
