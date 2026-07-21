from datetime import datetime

from pydantic import BaseModel, ConfigDict


class Case(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    sample_sha256: str
    original_name: str
    status: str
    created_at: datetime
    analysis_profile: str
