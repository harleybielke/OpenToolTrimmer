from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Decision(str, Enum):
    ACQUIRE = "ACQUIRE"
    POINT_ONLY = "POINT_ONLY"
    HOLD = "HOLD"


@dataclass
class LicenseFinding:
    spdx_id: str | None
    path: str | None
    confidence: str
    reason: str


@dataclass
class CandidateFunction:
    file: str
    name: str
    line_start: int
    line_end: int
    score: int
    matched_terms: list[str] = field(default_factory=list)


@dataclass
class AnalysisReceipt:
    opentooltrimmer_version: str
    invocation_correlation_id: str | None
    requested_capability: str
    intended_use: str
    source: str
    source_revision: str | None
    source_snapshot_sha256: str
    selected: CandidateFunction | None
    same_file_helpers: list[str]
    stdlib_imports: list[str]
    third_party_imports: list[str]
    unresolved_project_imports: list[str]
    dependency_complete_v0_1: bool
    license: LicenseFinding
    acquisition_allowlist: list[str]
    decision: Decision
    decision_reason: str
    code_emitted: bool
    source_repository_bytes: int
    emitted_slice_bytes: int
    trimmed_bytes: int
    trim_ratio: float
    verification_status: str
    verification_reason: str

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["decision"] = self.decision.value
        return data
