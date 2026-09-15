import os

from .notification_dispatcher import NotificationDispatcher, RateLimiter, RoutingRule, Channel, Severity


CUSTOM_ROUTING = {
    "critical_pagerduty": RoutingRule(
        channels=[Channel.SLACK, Channel.PAGERDUTY, Channel.EMAIL],
        min_severity=Severity.CRITICAL,
    ),
    "high_pagerduty": RoutingRule(
        channels=[Channel.SLACK, Channel.PAGERDUTY],
        min_severity=Severity.HIGH,
    ),
    "medium_infra_sec": RoutingRule(
        channels=[Channel.SLACK],
        min_severity=Severity.MEDIUM,
        categories=["infrastructure", "security"],
    ),
    "low_compliance": RoutingRule(
        channels=[Channel.EMAIL],
        min_severity=Severity.LOW,
        categories=["compliance"],
    ),
}


def build_dispatcher() -> NotificationDispatcher:
    slack_webhook = os.getenv("SLACK_WEBHOOK_URL", "")
    pagerduty_key = os.getenv("PAGERDUTY_ROUTING_KEY", "")
    rate_max = int(os.getenv("NOTIFY_RATE_LIMIT_MAX", "10"))
    rate_window = int(os.getenv("NOTIFY_RATE_LIMIT_WINDOW", "60"))

    return NotificationDispatcher(
        slack_webhook=slack_webhook,
        pagerduty_key=pagerduty_key,
        routing_rules=CUSTOM_ROUTING,
        rate_limiter=RateLimiter(max_requests=rate_max, window_seconds=rate_window),
        email_config={"recipients": os.getenv("EMAIL_RECIPIENTS", "").split(",") if os.getenv("EMAIL_RECIPIENTS") else []},
    )