from pydantic import BaseModel, ConfigDict


class ImportResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    sample_sha256: str
    project_dir: str
    program_name: str
    analyzed: bool
    skipped: bool
    warnings: list[str]


class FunctionInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    address: str
    name: str
    size: int


class DecompiledFunction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    address: str
    name: str
    pseudocode: str
    callers: list[str]
    callees: list[str]
    referenced_strings: list[str]


class CrossReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    direction: str
    source_address: str
    target_address: str
    reference_type: str
