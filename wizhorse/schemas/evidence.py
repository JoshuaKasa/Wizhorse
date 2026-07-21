from pydantic import BaseModel, ConfigDict, Field


class EvidenceReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    artifact_id: str | None = None
    function_address: str | None = None
    observation: str


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim: str
    status: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[EvidenceReference]
    limitations: list[str]
