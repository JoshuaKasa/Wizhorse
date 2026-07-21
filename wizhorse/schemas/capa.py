from pydantic import BaseModel, ConfigDict


class CapaMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule: str
    namespace: str | None = None
    locations: list[str]


class CapaResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    sample_sha256: str
    supported: bool
    matched: bool
    matches: list[CapaMatch]
    warnings: list[str]
    error: str | None = None
