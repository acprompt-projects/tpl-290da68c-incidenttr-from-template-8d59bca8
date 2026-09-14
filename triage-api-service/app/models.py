from __future__ import annotations

import enum
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    TRIAGING = "triaging"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


class AlertSource(str, enum.Enum):
    RULES_ENGINE = "rules_engine"
    MANUAL = "manual"
    INGESTION = "ingestion"


class Alert(BaseModel):
    alert_id: str
    source: AlertSource = AlertSource.RULES_ENGINE
    rule_name: str
    description: str
    raw_payload: dict = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class IncidentCreate(BaseModel):
    title: str
    description: str
    severity: Severity = Severity.MEDIUM
    alerts: list[Alert] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)
    assignee: Optional[str] = None


class TriageUpdate(BaseModel):
    severity: Optional[Severity] = None
    status: Optional[IncidentStatus] = None
    assignee: Optional[str] = None
    tags: Optional[dict[str, str]] = None
    notes: Optional[str] = None


class IncidentResponse(BaseModel):
    id: str
    title: str
    description: str
    severity: Severity
    status: IncidentStatus = IncidentStatus.OPEN
    alerts: list[Alert] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)
    assignee: Optional[str] = None
    notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class ErrorResponse(BaseModel):
    detail: str
    code: int