# llm/validator.py

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

class ScamDetectionOutput(BaseModel):
    """The only response shape accepted from the Gemini scam classifier."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    label: Literal["Scam", "Not Scam", "Uncertain"] = Field(
        ..., description="Scam | Not Scam | Uncertain"
    )
    reasoning: str = Field(..., min_length=1, description="Explanation of the assigned label")
    intent: str = Field(..., min_length=1, description="Short description of the sender's intent")
    risk_factors: list[str] = Field(..., description="List of identified red flags")

    @field_validator("risk_factors")
    @classmethod
    def validate_risk_factors(cls, risk_factors: list[str]) -> list[str]:
        """Require a JSON array of non-empty strings, not a prose string."""
        if any(not factor.strip() for factor in risk_factors):
            raise ValueError("risk_factors must not contain empty values")
        return risk_factors

def validate_output(response: dict) -> ScamDetectionOutput:
    """
    Validate and return structured ScamDetectionOutput model.
    If validation fails, raise a clear error.
    """
    try:
        return ScamDetectionOutput.model_validate(response)
    except ValidationError as error:
        raise ValueError(f"LLM output failed schema validation: {error}") from error
