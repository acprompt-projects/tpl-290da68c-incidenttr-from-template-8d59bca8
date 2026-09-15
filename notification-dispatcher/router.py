import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from .notification_dispatcher import (
    Channel, Incident, NotificationDispatcher, RateLimiter, RoutingRule, Severity,
)

logger = logging.getLogger(__name__)

dispatcher: Optional[NotificationDispatcher] = None


class IncidentPayload(BaseModel):
    id: str
    title: str
    severity: str = Field(pattern=r"^(critical|high|medium|low|info)$")
    category: str
    description: str = ""
    metadata: dict = Field(default_factory=dict)


class DispatchResponse(BaseModel):
    incident_id: str
    channels_targeted: list[str]
    results: list[dict]


class ConfigResponse(BaseModel):
    routing_rules: dict[str, dict]
    configured_channels: list[str]


router = APIRouter(prefix="/notifications", tags=["notifications"])


def get_dispatcher() -> NotificationDispatcher:
    global dispatcher
    if dispatcher is None:
        from .config import build_dispatcher
        dispatcher = build_dispatcher()
    return dispatcher


@router.post("/dispatch", response_model=DispatchResponse)
async def dispatch_incident(payload: IncidentPayload):
    disp = get_dispatcher()
    incident = Incident(
        id=payload.id, title=payload.title, severity=Severity(payload.severity),
        category=payload.category, description=payload.description, metadata=payload.metadata,
    )
    channels = disp.resolve_channels(incident)
    results = await disp.dispatch(incident)
    return DispatchResponse(
        incident_id=incident.id,
        channels_targeted=[c.value for c in channels],
        results=results,
    )


@router.get("/config", response_model=ConfigResponse)
async def get_config():
    disp = get_dispatcher()
    rules = {}
    for name, rule in disp.routing_rules.items():
        rules[name] = {
            "channels": [c.value for c in rule.channels],
            "min_severity": rule.min_severity.value,
            "categories": rule.categories,
        }
    return ConfigResponse(
        routing_rules=rules,
        configured_channels=[ch.value for ch in disp._notifiers.keys()],
    )


@router.get("/rate-limit-status")
async def rate_limit_status(key: str = Query(..., description="Rate limit key to check")):
    disp = get_dispatcher()
    now = __import__("time").time()
    cutoff = now - disp.rate_limiter.window_seconds
    entries = [t for t in disp.rate_limiter._timestamps.get(key, []) if t > cutoff]
    return {"key": key, "current_count": len(entries), "max": disp.rate_limiter.max_requests,
            "window_seconds": disp.rate_limiter.window_seconds, "allowed": len(entries) < disp.rate_limiter.max_requests}