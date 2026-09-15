import time
import hashlib
import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import Any, Optional
from collections import defaultdict

import httpx

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Channel(str, Enum):
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    EMAIL = "email"


@dataclass
class Incident:
    id: str
    title: str
    severity: Severity
    category: str
    description: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class RoutingRule:
    channels: list[Channel]
    min_severity: Severity = Severity.LOW
    categories: list[str] = field(default_factory=list)

    SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

    def matches(self, incident: Incident) -> bool:
        sev_idx = self.SEVERITY_ORDER.index(self.min_severity)
        inc_idx = self.SEVERITY_ORDER.index(incident.severity)
        if inc_idx < sev_idx:
            return False
        if self.categories and incident.category not in self.categories:
            return False
        return True


class RateLimiter:
    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._timestamps: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        cutoff = now - self.window_seconds
        self._timestamps[key] = [t for t in self._timestamps[key] if t > cutoff]
        if len(self._timestamps[key]) >= self.max_requests:
            return False
        self._timestamps[key].append(now)
        return True


class SlackNotifier:
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        self.client = httpx.AsyncClient(timeout=10.0)

    async def send(self, incident: Incident) -> dict:
        severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}
        emoji = severity_emoji.get(incident.severity.value, "⚪")
        payload = {
            "text": f"{emoji} [{incident.severity.value.upper()}] {incident.title}",
            "blocks": [
                {"type": "section", "text": {"type": "mrkdwn",
                 "text": f"*{emoji} Incident {incident.id}*\n*Severity:* {incident.severity.value.upper()}\n*Category:* {incident.category}\n{incident.description}"}}
            ],
        }
        try:
            resp = await self.client.post(self.webhook_url, json=payload)
            return {"channel": "slack", "status": resp.status_code, "incident_id": incident.id}
        except Exception as e:
            logger.error("Slack send failed: %s", e)
            return {"channel": "slack", "status": "error", "error": str(e), "incident_id": incident.id}


class PagerDutyNotifier:
    def __init__(self, routing_key: str, api_url: str = "https://events.pagerduty.com/v2/enqueue"):
        self.routing_key = routing_key
        self.api_url = api_url
        self.client = httpx.AsyncClient(timeout=10.0)

    async def send(self, incident: Incident) -> dict:
        severity_map = {"critical": "critical", "high": "critical", "medium": "warning", "low": "info", "info": "info"}
        payload = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": incident.title,
                "severity": severity_map.get(incident.severity.value, "info"),
                "source": incident.id,
                "component": incident.category,
                "custom_details": {"description": incident.description, **incident.metadata},
            },
        }
        try:
            resp = await self.client.post(self.api_url, json=payload)
            return {"channel": "pagerduty", "status": resp.status_code, "incident_id": incident.id}
        except Exception as e:
            logger.error("PagerDuty send failed: %s", e)
            return {"channel": "pagerduty", "status": "error", "error": str(e), "incident_id": incident.id}


class EmailNotifier:
    def __init__(self, smtp_host: str = "localhost", smtp_port: int = 587, recipients: Optional[list[str]] = None):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.recipients = recipients or []

    async def send(self, incident: Incident) -> dict:
        logger.info("Email notification for incident %s to %s", incident.id, self.recipients)
        return {"channel": "email", "status": "queued", "incident_id": incident.id, "recipients": self.recipients}


DEFAULT_ROUTING: dict[str, RoutingRule] = {
    "critical_all": RoutingRule(channels=[Channel.SLACK, Channel.PAGERDUTY, Channel.EMAIL], min_severity=Severity.CRITICAL),
    "high_all": RoutingRule(channels=[Channel.SLACK, Channel.PAGERDUTY], min_severity=Severity.HIGH),
    "medium_slack": RoutingRule(channels=[Channel.SLACK], min_severity=Severity.MEDIUM, categories=["infrastructure", "security"]),
    "low_email": RoutingRule(channels=[Channel.EMAIL], min_severity=Severity.LOW, categories=["compliance"]),
}


class NotificationDispatcher:
    def __init__(
        self,
        slack_webhook: str = "",
        pagerduty_key: str = "",
        routing_rules: Optional[dict[str, RoutingRule]] = None,
        rate_limiter: Optional[RateLimiter] = None,
        email_config: Optional[dict] = None,
    ):
        self.routing_rules = routing_rules or DEFAULT_ROUTING
        self.rate_limiter = rate_limiter or RateLimiter()
        self._notifiers: dict[Channel, Any] = {}
        if slack_webhook:
            self._notifiers[Channel.SLACK] = SlackNotifier(slack_webhook)
        if pagerduty_key:
            self._notifiers[Channel.PAGERDUTY] = PagerDutyNotifier(pagerduty_key)
        self._notifiers[Channel.EMAIL] = EmailNotifier(**(email_config or {}))

    def resolve_channels(self, incident: Incident) -> list[Channel]:
        channels: set[Channel] = set()
        for rule in self.routing_rules.values():
            if rule.matches(incident):
                channels.update(rule.channels)
        return list(channels)

    async def dispatch(self, incident: Incident) -> list[dict]:
        rate_key = hashlib.md5(f"{incident.id}:{incident.severity.value}".encode()).hexdigest()
        if not self.rate_limiter.is_allowed(rate_key):
            logger.warning("Rate limited incident %s", incident.id)
            return [{"incident_id": incident.id, "status": "rate_limited"}]

        channels = self.resolve_channels(incident)
        results = []
        for ch in channels:
            notifier = self._notifiers.get(ch)
            if notifier:
                try:
                    result = await notifier.send(incident)
                    results.append(result)
                except Exception as e:
                    logger.error("Dispatch to %s failed: %s", ch.value, e)
                    results.append({"channel": ch.value, "status": "error", "error": str(e)})
            else:
                logger.warning("No notifier configured for channel %s", ch.value)
                results.append({"channel": ch.value, "status": "not_configured"})
        return results