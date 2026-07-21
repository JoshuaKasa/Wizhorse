from __future__ import annotations

from typing import Any

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic_core import PydanticCustomError


class EvidenceReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str = Field(validation_alias=AliasChoices("source", "type"))
    artifact_id: str | None = None
    function_address: str | None = None
    observation: str

    @model_validator(mode="before")
    @classmethod
    def normalize_source_alias(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        if "source" in value and "type" in value:
            normalized = dict(value)
            normalized.pop("type")
            return normalized
        return value


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim: str
    status: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[EvidenceReference]
    limitations: list[str]

    @field_validator("confidence", mode="before")
    @classmethod
    def normalize_confidence(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value

        normalized = value.strip().lower()
        confidence_map = {
            # Fixed mappings keep stored confidence numeric while accepting
            # the recurring analyst shorthand used in MCP tool payloads.
            "low": 0.3,
            "medium": 0.6,
            "high": 0.85,
        }
        if normalized in confidence_map:
            return confidence_map[normalized]

        raise PydanticCustomError(
            "confidence_value",
            "confidence must be one of low, medium, high or a number between 0 and 1, got {value}",
            {"value": value},
        )
