from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from .models import (
    ErrorResponse,
    IncidentCreate,
    IncidentResponse,
    IncidentStatus,
    Severity,
    TriageUpdate,
)

logger = logging.getLogger("triage-api")
app = FastAPI(title="Incident Triage Service", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_incidents: dict[str, IncidentResponse] = {}


def _dedupe_key(title: str, alerts: list) -> str:
    parts = [title.lower().strip()]
    for a in alerts[:5]:
        parts.append(a.alert_id)
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def _classify_severity(incident: IncidentCreate) -> Severity:
    keywords = {
        Severity.CRITICAL: ["outage", "data_loss", "breach", "down"],
        Severity.HIGH: ["degradation", "failover", "error_spike"],
        Severity.LOW: ["info", "notice", "flap"],
    }
    text = (incident.title + " " + incident.description).lower()
    for sev, words in keywords.items():
        if any(w in text for w in words):
            return sev
    return incident.severity


def _notify_slack(incident: IncidentResponse) -> None:
    logger.info("Slack notification for incident %s severity=%s", incident.id, incident.severity.value)


def _notify_pagerduty(incident: IncidentResponse) -> None:
    if incident.severity in (Severity.CRITICAL, Severity.HIGH):
        logger.info("PagerDuty alert for incident %s severity=%s", incident.id, incident.severity.value)


@app.post(
    "/incidents",
    response_model=IncidentResponse,
    status_code=status.HTTP_201_CREATED,
    responses={409: {"model": ErrorResponse}},
)
def create_incident(body: IncidentCreate) -> IncidentResponse:
    dedupe = _dedupe_key(body.title, body.alerts)
    for existing in _incidents.values():
        if existing.status != IncidentStatus.RESOLVED and _dedupe_key(existing.title, existing.alerts) == dedupe:
            raise HTTPException(status_code=409, detail=f"Duplicate of incident {existing.id}")

    now = datetime.utcnow()
    severity = _classify_severity(body)
    incident = IncidentResponse(
        id=str(uuid.uuid4()),
        title=body.title,
        description=body.description,
        severity=severity,
        alerts=body.alerts,
        tags=body.tags,
        assignee=body.assignee,
        created_at=now,
        updated_at=now,
    )
    _incidents[incident.id] = incident
    _notify_slack(incident)
    _notify_pagerduty(incident)
    logger.info("Created incident %s severity=%s", incident.id, severity.value)
    return incident


@app.get(
    "/incidents/{incident_id}",
    response_model=IncidentResponse,
    responses={404: {"model": ErrorResponse}},
)
def get_incident(incident_id: str) -> IncidentResponse:
    incident = _incidents.get(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.patch(
    "/incidents/{incident_id}/triage",
    response_model=IncidentResponse,
    responses={404: {"model": ErrorResponse}},
)
def update_triage(incident_id: str, body: TriageUpdate) -> IncidentResponse:
    incident = _incidents.get(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    update_data = body.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        if field == "notes":
            existing = incident.notes or ""
            value = existing + ("\n" if existing else "") + value
        setattr(incident, field, value)

    if body.severity and body.severity != incident.severity:
        incident.severity = body.severity
        _notify_pagerduty(incident)

    incident.status = IncidentStatus.TRIAGING
    incident.updated_at = datetime.utcnow()
    _incidents[incident_id] = incident
    logger.info("Triage updated for incident %s", incident_id)
    return incident


@app.get("/incidents", response_model=list[IncidentResponse])
def list_incidents(
    severity: Optional[Severity] = None,
    status_filter: Optional[IncidentStatus] = None,
    limit: int = 50,
) -> list[IncidentResponse]:
    results = list(_incidents.values())
    if severity:
        results = [i for i in results if i.severity == severity]
    if status_filter:
        results = [i for i in results if i.status == status_filter]
    return sorted(results, key=lambda i: i.created_at, reverse=True)[:limit]


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}