from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pidg.core.models import digest


@dataclass(frozen=True)
class Source:
    source_id: str
    source_type: str
    trust_level: str
    content_hash: str
    retrieval_time: str
    origin: str
    data_labels: frozenset[str]
    parent_sources: tuple[str, ...] = ()

    def public_metadata(self) -> dict[str, Any]:
        data = asdict(self)
        data["data_labels"] = sorted(self.data_labels)
        return data


class ProvenanceTracker:
    def __init__(self) -> None:
        self.sources: dict[str, Source] = {}

    def external(
        self, content: Any, source_type: str, origin: str, labels: frozenset[str] = frozenset()
    ) -> Source:
        source = Source(
            uuid4().hex,
            source_type,
            "untrusted",
            digest(content),
            datetime.now(UTC).isoformat(),
            origin,
            labels | {"unverified"},
        )
        self.sources[source.source_id] = source
        return source

    @property
    def labels(self) -> frozenset[str]:
        return frozenset().union(*(s.data_labels for s in self.sources.values()))
