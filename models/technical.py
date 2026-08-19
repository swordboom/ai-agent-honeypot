"""Wire model for pre-parsed technical security events."""

from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class TechnicalEvent(BaseModel):
    eventId: str
    timestamp: float
    eventType: str
    sourceIdentifier: str
    targetIdentifiers: List[str] = Field(default_factory=list)
    indicators: Dict[str, List[str]] = Field(default_factory=dict)
    count: int = Field(ge=0)
    confidence: float = Field(ge=0.0, le=1.0)
    detectionSource: str
    succeededAfterFailures: bool = False
    metadata: Optional[Dict[str, object]] = None
