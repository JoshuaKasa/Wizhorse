from pydantic import BaseModel, ConfigDict


class YaraStringMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identifier: str
    offset: int
    data: str | None = None


class YaraMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule: str
    namespace: str | None = None
    tags: list[str]
    strings: list[YaraStringMatch]


class YaraResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    sample_sha256: str
    rule_dir: str
    matched: bool
    matches: list[YaraMatch]
    warnings: list[str]
    error: str | None = None
