"""Declared source exposure and fail-closed class authorization."""

from dataclasses import dataclass
from enum import Enum


class SourceClass(str, Enum):
    LOCAL = "LOCAL"
    PASSIVE_WEB = "PASSIVE_WEB"
    THIRD_PARTY_API = "THIRD_PARTY_API"
    TOR = "TOR"
    DIRECT_TARGET = "DIRECT_TARGET"


@dataclass(frozen=True)
class SourcePolicy:
    allowed: frozenset[SourceClass] = frozenset({SourceClass.LOCAL})

    def __post_init__(self) -> None:
        if any(not isinstance(item, SourceClass) for item in self.allowed):
            raise ValueError("allowed must contain only SourceClass values")

    def permits(self, source_class: SourceClass) -> bool:
        if not isinstance(source_class, SourceClass):
            raise ValueError("unknown source class")
        return source_class in self.allowed
