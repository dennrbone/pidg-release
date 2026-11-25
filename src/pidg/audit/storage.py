from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from pidg.core.models import canonical


class AuditLog:
    """Value-free events: neither arguments, results nor exception messages are logged."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    def append(self, event: dict[str, Any]) -> None:
        data = (canonical(event) + "\n").encode()
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        try:
            if os.write(fd, data) != len(data):
                raise OSError("incomplete audit write")
            os.fsync(fd)
        finally:
            os.close(fd)

    def events(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text().splitlines() if line]
