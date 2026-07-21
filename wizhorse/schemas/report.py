from pydantic import BaseModel, ConfigDict


class ReportSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    sample_sha256: str
    report_path: str
    content: str
