from __future__ import annotations

import base64
import html
import json
import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import unquote


@dataclass(frozen=True)
class Scan:
    risk: float
    findings: tuple[str, ...]
    labels: frozenset[str]


PATTERNS = {
    "ROLE_SPOOFING": r"(<\|?(system|developer)\|?>|\[system\]|system\s*:|系统指令)",
    "HIERARCHY_OVERRIDE": r"(ignore.{0,35}(instructions|rules)|игнориру\w*.{0,35}(инструкц|правил)|ignora.{0,30}instrucciones|忽略.{0,15}指令)",
    "AUTHORITY_SPOOFING": r"(administrator.{0,30}(approved|override)|администратор.{0,30}(разреш|приказ)|highest priority)",
    "SECRET_REQUEST": r"(exfiltrat|reveal.{0,30}(secret|token|key)|раскр\w*.{0,30}(секрет|токен)|send.{0,30}canary)",
    "SECURITY_CHANGE": r"(disable.{0,30}(guard|security|policy)|отключ\w*.{0,30}(защит|политик)|trust\s*[:=]\s*true)",
    "MEMORY_POISONING": r"((remember|запомни|persist).{0,60}(always|instruction|правил|system))",
    "TOOL_POISONING": r"(\b(call|invoke|execute|run)\s+(?:(?:the|a)\s+)?(?:tool\b|function\b|command\b|[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b|[a-z][a-z0-9_]*\s*\()|вызови.{0,40}(инструмент|функци)|запусти.{0,40}команд)",
}
SECRET_PATTERN = re.compile(
    r"(?<![A-Z0-9])(?:[A-Z0-9]+_)*(?:CANARY|HONEYTOKEN)_[A-Z0-9_]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\b(?:sk-[A-Za-z0-9_-]{16,}|AKIA[A-Z0-9]{16})\b|"
    r"(?:api[_-]?key|password|secret|token)\s*[:=]\s*[\"']?[^\s\"',}]{6,}",
    re.I,
)


def normalize_content(text: str) -> tuple[str, bool]:
    normalized = unicodedata.normalize("NFKC", html.unescape(unquote(text)))
    hidden = any(unicodedata.category(c) == "Cf" for c in normalized)
    if hidden:
        normalized = "".join(c for c in normalized if unicodedata.category(c) != "Cf")
    variants = [normalized]
    for token in re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", normalized)[:32]:
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8")
            variants.append(decoded)
        except (ValueError, UnicodeError):
            continue
    return "\n".join(variants), hidden


def secret_labels(text: str, *, protected_values: tuple[str, ...] = ()) -> frozenset[str]:
    """Data classification is independent of instruction detection and never authorizes."""
    if len(text) > 1_000_000:
        return frozenset({"unverified"})
    combined, _ = normalize_content(text)
    protected = tuple(
        variant
        for value in protected_values
        for variant in (
            value,
            normalize_content(value)[0].split("\n")[0],
            base64.b64encode(value.encode()).decode().rstrip("="),
            base64.urlsafe_b64encode(value.encode()).decode().rstrip("="),
        )
        if variant
    )
    if any(value in combined for value in protected):
        return frozenset({"secret"})

    def structured(value: object, depth: int = 0) -> bool:
        if depth > 12:
            return True  # Fail closed on nested encoded data beyond the classification budget.
        if isinstance(value, dict):
            sensitive = {
                "password",
                "secret",
                "apikey",
                "token",
                "accesstoken",
                "authorization",
                "privatekey",
            }
            return any(
                (
                    re.sub(r"[_-]", "", str(key).casefold()) in sensitive
                    and isinstance(item, (str, int, float))
                    and bool(item)
                )
                or structured(item, depth + 1)
                for key, item in value.items()
            )
        if isinstance(value, list):
            return any(structured(item, depth + 1) for item in value)
        if isinstance(value, str):
            if any(item in value for item in protected):
                return True
            if SECRET_PATTERN.search(value):
                return True
            if value.lstrip().startswith(("{", "[", '"')):
                try:
                    return structured(json.loads(value), depth + 1)
                except ValueError:
                    return False
                except RecursionError:
                    return True
        return False

    return (
        frozenset({"secret"})
        if SECRET_PATTERN.search(combined)
        or structured(text)
        or any(structured(line) for line in combined.splitlines())
        else frozenset()
    )


class InputGuard:
    def __init__(
        self,
        classifier: Callable[[str], float] | None = None,
        *,
        protected_values: tuple[str, ...] = (),
    ) -> None:
        self.classifier = classifier
        self.protected_values = protected_values

    def scan(self, text: str, context: str = "document") -> Scan:
        findings: list[str] = []
        if len(text) > 1_000_000:
            return Scan(1.0, ("CONTENT_TOO_LARGE",), frozenset({"unverified"}))
        combined, hidden = normalize_content(text)
        if hidden:
            findings.append("HIDDEN_FORMATTING")
        for name, pattern in PATTERNS.items():
            if re.search(pattern, combined, re.I | re.S):
                findings.append(name)
        if context in {"tool_description", "tool_result"} and findings:
            findings.append(
                "TOOL_DESCRIPTION_POISONING"
                if context == "tool_description"
                else "TOOL_OUTPUT_POISONING"
            )
        if context == "memory" and findings:
            findings.append("MEMORY_INSTRUCTION")
        score = min(1.0, len(findings) * 0.3)
        if self.classifier:
            classified = self.classifier(text)
            if not 0 <= classified <= 1:
                raise ValueError("invalid classifier score")
            score = max(score, classified)
        labels = secret_labels(text, protected_values=self.protected_values)
        return Scan(score, tuple(findings), labels)
