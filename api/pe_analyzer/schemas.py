from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AnalyzeFileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1, max_length=4096)

    @field_validator("path")
    @classmethod
    def path_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("A file path is required.")
        return value


class AnalysisError(BaseModel):
    code: str
    message: str


class SectionIndicators(BaseModel):
    name: str
    virtual_size: int
    raw_size: int
    entropy: float | None
    readable: bool
    writable: bool
    executable: bool
    characteristics: int


class ImportIndicators(BaseModel):
    dll: str
    apis: list[str] = Field(default_factory=list)


class PEAnalysisResponse(BaseModel):
    status: Literal["ANALYZED", "INVALID_PE", "REJECTED_PATH", "UNSUPPORTED_FILE", "ANALYSIS_ERROR"]
    file_name: str | None = None
    sha256: str | None = None
    file_size_bytes: int | None = None
    pe_valid: bool | None = None
    architecture: str | None = None
    section_count: int | None = None
    sections: list[SectionIndicators] = Field(default_factory=list)
    imports: list[ImportIndicators] = Field(default_factory=list)
    sensitive_imports: list[str] = Field(default_factory=list)
    anomalies: list[str] = Field(default_factory=list)
    suspicious_indicators: list[str] = Field(default_factory=list)
    risk_score: int | None = None
    risk_score_explanation: str = (
        "When present, this is a deterministic structural heuristic, not a calibrated probability of malware or a malware verdict."
    )
    error: AnalysisError | None = None
