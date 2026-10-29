"""
SecureUpload Inspector - Heuristic Risk Assessment Module
=========================================================
Computes an audited, bounded heuristic risk score from rule findings.

IMPORTANT CYBERSECURITY DISCLAIMER:
The computed risk score (0-100) measures deviations from file formatting standards,
suspicious metadata discrepancies, and security policy non-compliance.
IT IS NOT A PROBABILITY OF MALWARE OR AN ANTI-VIRUS VERDICT.
File validation confirms structural and policy compliance; it does not guarantee
that a structurally compliant file is free from embedded zero-day exploit payloads.
"""

from dataclasses import dataclass, asdict
from typing import Sequence

DEFAULT_SEVERITY_WEIGHTS = {
    "CRITICAL": 45,
    "HIGH": 30,
    "MEDIUM": 15,
    "LOW": 5,
    "INFO": 0,
}

@dataclass
class RiskAssessmentResult:
    """Structured output of the heuristic risk calculation."""
    score: int                  # Bounded 0 - 100
    level: str                  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    contributing_factors: list[dict]
    weights_applied: dict[str, int]
    disclaimer: str

    def to_dict(self) -> dict:
        return asdict(self)


def calculate_risk_score(
    findings: Sequence[dict],
    custom_weights: dict[str, int] | None = None
) -> RiskAssessmentResult:
    """
    Calculate an auditable risk score based on policy findings.
    
    Prevents duplicate penalties by keying on unique rule_id values
    and caps the total score at 100.
    
    Args:
        findings: List of finding dictionaries with keys: rule_id, severity, status
        custom_weights: Optional override dictionary of severity weights
        
    Returns:
        RiskAssessmentResult containing capped score, risk tier, and itemized breakdown.
    """
    weights = custom_weights or DEFAULT_SEVERITY_WEIGHTS
    seen_rule_ids: set[str] = set()
    contributing_factors: list[dict] = []
    accumulated_score = 0

    for finding in findings:
        status = finding.get("status", "").upper()
        # Only evaluate findings that indicate failure or warnings
        if status not in {"FAIL", "WARN"}:
            continue

        rule_id = finding.get("rule_id", "UNKNOWN")
        # Prevent duplicate penalties for the same rule ID
        if rule_id in seen_rule_ids:
            continue
        seen_rule_ids.add(rule_id)

        severity = finding.get("severity", "LOW").upper()
        # In case of WARN, scale down severity weight by 50%
        base_weight = weights.get(severity, 5)
        weight_impact = base_weight if status == "FAIL" else max(1, base_weight // 2)

        accumulated_score += weight_impact
        contributing_factors.append({
            "rule_id": rule_id,
            "title": finding.get("title", ""),
            "severity": severity,
            "status": status,
            "weight_impact": weight_impact
        })

    # Hard cap at 100 and floor at 0
    final_score = min(100, max(0, accumulated_score))

    # Categorize risk level
    if final_score >= 70:
        level = "CRITICAL"
    elif final_score >= 40:
        level = "HIGH"
    elif final_score >= 15:
        level = "MEDIUM"
    else:
        level = "LOW"

    disclaimer = (
        "The risk score is a deterministic heuristic validation score measuring policy and "
        "specification deviations. It is NOT a probabilistic malware detection score or anti-virus verdict."
    )

    return RiskAssessmentResult(
        score=final_score,
        level=level,
        contributing_factors=contributing_factors,
        weights_applied=weights,
        disclaimer=disclaimer
    )
