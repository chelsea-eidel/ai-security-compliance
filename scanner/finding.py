"""Canonical finding model shared across all scanners and parsers."""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Optional


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        return cls[value.upper()]


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: Severity
    category: str
    file_path: str
    line_start: int = 0
    line_end: int = 0
    snippet: str = ""
    message: str = ""
    tool: str = ""
    repo: str = ""
    remediation_strategy: str = ""
    ai_assisted: bool = False
    metadata: dict = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        raw = f"{self.repo}:{self.rule_id}:{self.file_path}:{self.line_start}:{self.snippet[:80]}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.name
        d["fingerprint"] = self.fingerprint
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        data = dict(data)
        data.pop("fingerprint", None)
        if isinstance(data.get("severity"), str):
            data["severity"] = Severity.from_str(data["severity"])
        return cls(**data)
