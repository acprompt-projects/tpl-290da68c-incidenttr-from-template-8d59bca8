from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class Category(Enum):
    INFRA = "infra"
    APP = "app"
    SECURITY = "security"
    NETWORK = "network"


@dataclass(frozen=True)
class TriageLabel:
    severity: Severity
    category: Category
    confidence: float
    rule_id: str
    suppress: bool = False


@dataclass
class ClassificationThresholds:
    error_rate_critical: float = 0.5
    error_rate_high: float = 0.2
    error_rate_medium: float = 0.05
    latency_ms_critical: float = 5000
    latency_ms_high: float = 2000
    latency_ms_medium: float = 500
    affected_hosts_critical: int = 10
    affected_hosts_high: int = 5
    affected_hosts_medium: int = 2
    security_score_critical: float = 9.0
    security_score_high: float = 7.0
    packet_loss_pct_critical: float = 50.0
    packet_loss_pct_high: float = 20.0
    packet_loss_pct_medium: float = 5.0


_CATEGORY_KEYWORDS: dict[Category, list[str]] = {
    Category.INFRA: ["cpu", "memory", "disk", "host", "node", "pod", "container", "vm", "instance", "out_of_memory", "oom"],
    Category.APP: ["error", "exception", "crash", "timeout", "500", "503", "4xx", "5xx", "latency", "response_time"],
    Category.SECURITY: ["auth", "unauthorized", "breach", "vulnerability", "cve", "intrusion", "malware", "phishing", "token", "certificate", "ssl"],
    Category.NETWORK: ["dns", "connection", "packet_loss", "latency_spike", "bandwidth", "tcp", "routing", "firewall", "drop", "unreachable"],
}


@dataclass
class Incident:
    source: str
    title: str
    labels: dict[str, str] = field(default_factory=dict)
    metrics: dict[str, Any] = field(default_factory=dict)


class IncidentClassifier:
    def __init__(self, thresholds: ClassificationThresholds | None = None) -> None:
        self.thresholds = thresholds or ClassificationThresholds()

    def classify(self, incident: Incident) -> TriageLabel:
        category = self._infer_category(incident)
        severity = self._infer_severity(incident, category)
        confidence = self._compute_confidence(incident, category)
        suppress = severity == Severity.P4 and confidence < 0.4
        rule_id = f"{category.value}-{severity.value}-{self._signature(incident)}"
        return TriageLabel(
            severity=severity,
            category=category,
            confidence=round(confidence, 3),
            rule_id=rule_id,
            suppress=suppress,
        )

    def _infer_category(self, incident: Incident) -> Category:
        text = f"{incident.title} {' '.join(incident.labels.values())}".lower()
        scores: dict[Category, int] = {c: 0 for c in Category}
        for cat, keywords in _CATEGORY_KEYWORDS.items():
            for kw in keywords:
                if kw in text:
                    scores[cat] += 1
        if incident.labels.get("category") in (c.value for c in Category):
            explicit = Category(incident.labels["category"])
            scores[explicit] += 10
        best = max(scores, key=scores.get)
        return best if scores[best] > 0 else Category.APP

    def _infer_severity(self, incident: Incident, category: Category) -> Severity:
        m = incident.metrics
        dispatchers = {
            Category.INFRA: self._severity_infra,
            Category.APP: self._severity_app,
            Category.SECURITY: self._severity_security,
            Category.NETWORK: self._severity_network,
        }
        return dispatchers[category](m)

    def _severity_infra(self, m: dict[str, Any]) -> Severity:
        hosts = m.get("affected_hosts", 1)
        cpu = m.get("cpu_pct", 0.0)
        if hosts >= self.thresholds.affected_hosts_critical or cpu >= 95:
            return Severity.P1
        if hosts >= self.thresholds.affected_hosts_high or cpu >= 85:
            return Severity.P2
        if hosts >= self.thresholds.affected_hosts_medium or cpu >= 70:
            return Severity.P3
        return Severity.P4

    def _severity_app(self, m: dict[str, Any]) -> Severity:
        rate = m.get("error_rate", 0.0)
        latency = m.get("latency_ms", 0.0)
        if rate >= self.thresholds.error_rate_critical or latency >= self.thresholds.latency_ms_critical:
            return Severity.P1
        if rate >= self.thresholds.error_rate_high or latency >= self.thresholds.latency_ms_high:
            return Severity.P2
        if rate >= self.thresholds.error_rate_medium or latency >= self.thresholds.latency_ms_medium:
            return Severity.P3
        return Severity.P4

    def _severity_security(self, m: dict[str, Any]) -> Severity:
        score = m.get("security_score", 0.0)
        if score >= self.thresholds.security_score_critical:
            return Severity.P1
        if score >= self.thresholds.security_score_high:
            return Severity.P2
        if score > 0:
            return Severity.P3
        return Severity.P4

    def _severity_network(self, m: dict[str, Any]) -> Severity:
        loss = m.get("packet_loss_pct", 0.0)
        if loss >= self.thresholds.packet_loss_pct_critical:
            return Severity.P1
        if loss >= self.thresholds.packet_loss_pct_high:
            return Severity.P2
        if loss >= self.thresholds.packet_loss_pct_medium:
            return Severity.P3
        return Severity.P4

    def _compute_confidence(self, incident: Incident, category: Category) -> float:
        text = f"{incident.title} {' '.join(incident.labels.values())}".lower()
        keywords = _CATEGORY_KEYWORDS[category]
        hits = sum(1 for kw in keywords if kw in text)
        base = min(hits / 3.0, 1.0)
        if incident.labels.get("category") == category.value:
            base = 0.5 + 0.5 * base
        return max(base, 0.1)

    @staticmethod
    def _signature(incident: Incident) -> str:
        raw = f"{incident.source}:{incident.title}"
        return hex(abs(hash(raw)) % (1 << 16))[2:]