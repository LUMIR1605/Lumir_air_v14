"""A collector provides observations, never final verification decisions."""

from abc import ABC, abstractmethod
from dataclasses import dataclass

from osint_lab.policies import SourceClass


@dataclass(frozen=True)
class Observation:
    raw_status: str
    raw_evidence_ref: str | None = None


class Agent(ABC):
    name: str
    source_class: SourceClass

    def __init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("agent name required")
        if not isinstance(self.source_class, SourceClass):
            raise ValueError("agent source_class required")

    @abstractmethod
    def collect(self, seed: str) -> list[Observation]:
        """Return raw observations; authorization belongs to a future orchestrator."""
