from pydantic import AliasChoices, BaseModel, ConfigDict, Field


class CapaMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_name: str = Field(validation_alias=AliasChoices("rule_name", "rule"))
    namespace: str = ""
    locations: list[str] = Field(default_factory=list)


class CapaResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    sample_sha256: str
    supported: bool
    matched: bool
    matches: list[CapaMatch]
    warnings: list[str]
    error: str | None = None
