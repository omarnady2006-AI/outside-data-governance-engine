"""
Dataset-Level Threat Aggregation

This module aggregates individual threat signals into a dataset-level risk summary.
It provides risk interpretation and prioritization without making enforcement decisions.

Purpose:
- Aggregate multiple ThreatSignal objects into dataset-level view
- Calculate overall risk level based on threat composition
- Identify top contributing threats for prioritization
- Generate human-readable risk summaries

Constraints:
- Advisory only - no APPROVE/REJECT/ACCEPT logic
- Pure data output - no printing or side effects
- Deterministic and explainable escalation rules
- Backward compatible with existing threat mapping
"""

from typing import List, Dict, Any, Literal, Optional
from dataclasses import dataclass, asdict
from collections import Counter
import logging

# Import from existing threat mapping module
try:
    from .threat_mapping import ThreatSignal
except ImportError:
    from threat_mapping import ThreatSignal

logger = logging.getLogger(__name__)


@dataclass
class DatasetRiskSummary:
    """
    Dataset-level risk summary aggregating multiple threat signals.
    
    Attributes:
        overall_risk_level: Derived risk level (low/warning/critical)
        total_threats: Total number of detected threats
        severity_breakdown: Count of threats by severity level
        property_breakdown: Count of threats by impacted property
        top_threats: List of most significant threats (ranked)
        escalation_reasons: Reasons why risk level was escalated
        summary_text: Human-readable risk summary
        threat_ids: List of all detected threat IDs
        confidence_stats: Statistics on threat confidence scores
    """
    overall_risk_level: Literal["low", "warning", "critical"]
    total_threats: int
    severity_breakdown: Dict[str, int]  # {high: N, medium: N, low: N}
    property_breakdown: Dict[str, int]  # {privacy: N, utility: N, consistency: N}
    top_threats: List[Dict[str, Any]]  # Top N threats by priority
    escalation_reasons: List[str]  # Why risk level was determined
    summary_text: str  # Human-readable summary
    threat_ids: List[str]  # All threat IDs detected
    confidence_stats: Dict[str, float]  # {avg: X, max: X, min: X}
    total_missing_metrics: int = 0  # Total missing metrics across threats
    has_uncertainty: bool = False  # Whether any uncertainty exists in assessment
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


# ============================================================================
# ESCALATION RULES (Deterministic Risk Level Calculation)
# ============================================================================

# These rules are evaluated in order. First match determines risk level.
ESCALATION_RULES = {
    "critical": [
        {
            "name": "high_severity_privacy_threat",
            "condition": lambda threats: any(
                t.severity == "high" and t.impacted_property == "privacy" 
                for t in threats
            ),
            "reason": "High severity privacy threat detected"
        },
        {
            "name": "multiple_high_severity_threats",
            "condition": lambda threats: sum(1 for t in threats if t.severity == "high") >= 2,
            "reason": "Multiple high severity threats detected"
        },
        {
            "name": "high_confidence_privacy_threat",
            "condition": lambda threats: any(
                t.impacted_property == "privacy" and t.confidence > 0.8 and t.severity in ["high", "medium"]
                for t in threats
            ),
            "reason": "High confidence privacy threat with elevated severity"
        },
    ],
    
    "warning": [
        {
            "name": "any_high_severity_threat",
            "condition": lambda threats: any(t.severity == "high" for t in threats),
            "reason": "At least one high severity threat detected"
        },
        {
            "name": "multiple_medium_privacy_threats",
            "condition": lambda threats: sum(
                1 for t in threats if t.severity == "medium" and t.impacted_property == "privacy"
            ) >= 2,
            "reason": "Multiple medium severity privacy threats detected"
        },
        {
            "name": "multiple_medium_threats",
            "condition": lambda threats: sum(1 for t in threats if t.severity == "medium") >= 3,
            "reason": "Multiple medium severity threats detected across properties"
        },
        {
            "name": "privacy_threat_with_medium_confidence",
            "condition": lambda threats: any(
                t.impacted_property == "privacy" and t.confidence > 0.6
                for t in threats
            ),
            "reason": "Privacy threat with significant confidence detected"
        },
    ],
    
    "low": [
        {
            "name": "only_low_severity_threats",
            "condition": lambda threats: all(t.severity == "low" for t in threats) and len(threats) > 0,
            "reason": "Only low severity threats detected"
        },
        {
            "name": "no_threats",
            "condition": lambda threats: len(threats) == 0,
            "reason": "No threats detected"
        },
    ]
}


# ============================================================================
# CORE AGGREGATION FUNCTION
# ============================================================================

def aggregate_dataset_threats(
    threat_signals: List[ThreatSignal],
    top_n: int = 5
) -> DatasetRiskSummary:
    """
    Aggregate individual threat signals into dataset-level risk summary.
    
    This function analyzes multiple threat signals and produces a comprehensive
    dataset-level risk assessment including:
    - Overall risk level (with escalation logic)
    - Threat distribution across severities and properties
    - Top contributing threats for prioritization
    - Human-readable summary
    
    Args:
        threat_signals: List of ThreatSignal objects from threat mapping
        top_n: Number of top threats to include in summary (default: 5)
        
    Returns:
        DatasetRiskSummary with complete risk assessment
        
    Example:
        >>> from governance_core.threat_mapping import map_metrics_to_threats
        >>> threats = map_metrics_to_threats(metrics)
        >>> summary = aggregate_dataset_threats(threats)
        >>> print(summary.overall_risk_level)
        'warning'
    """
    # Edge case: None input
    if threat_signals is None:
        logger.warning("Received None threat_signals, treating as empty list")
        threat_signals = []
    
    # Edge case: Not a list
    if not isinstance(threat_signals, list):
        logger.warning(f"Expected list, got {type(threat_signals)}, treating as empty")
        threat_signals = []
    
    # Edge case: Empty list or no threats
    if not threat_signals:
        # No threats case - return safe default
        return DatasetRiskSummary(
            overall_risk_level="low",
            total_threats=0,
            severity_breakdown={"high": 0, "medium": 0, "low": 0},
            property_breakdown={"privacy": 0, "utility": 0, "consistency": 0},
            top_threats=[],
            escalation_reasons=["No threats detected"],
            summary_text="No security or governance threats detected in dataset.",
            threat_ids=[],
            confidence_stats={"avg": 0.0, "max": 0.0, "min": 0.0},
            total_missing_metrics=0,
            has_uncertainty=False
        )
    
    # Calculate severity breakdown
    severity_counts = Counter(t.severity for t in threat_signals if hasattr(t, 'severity'))
    severity_breakdown = {
        "high": severity_counts.get("high", 0),
        "medium": severity_counts.get("medium", 0),
        "low": severity_counts.get("low", 0)
    }
    
    # Calculate property breakdown
    property_counts = Counter(t.impacted_property for t in threat_signals if hasattr(t, 'impacted_property'))
    property_breakdown = {
        "privacy": property_counts.get("privacy", 0),
        "utility": property_counts.get("utility", 0),
        "consistency": property_counts.get("consistency", 0)
    }
    
    # Determine overall risk level using escalation rules
    overall_risk, escalation_reasons = _determine_risk_level(threat_signals)
    
    # Rank and select top threats
    top_threats = _rank_top_threats(threat_signals, top_n)
    
    # Calculate confidence statistics (with defensive checks)
    confidences = [t.confidence for t in threat_signals if hasattr(t, 'confidence') and isinstance(t.confidence, (int, float))]
    if confidences:
        confidence_stats = {
            "avg": round(sum(confidences) / len(confidences), 3),
            "max": round(max(confidences), 3),
            "min": round(min(confidences), 3)
        }
    else:
        confidence_stats = {"avg": 0.0, "max": 0.0, "min": 0.0}
    
    # Calculate uncertainty metrics
    total_missing = sum(getattr(t, 'missing_metrics', 0) for t in threat_signals)
    has_uncertainty = any(getattr(t, 'uncertainty_notes', []) for t in threat_signals)
    
    # Generate human-readable summary
    summary_text = _generate_summary_text(
        overall_risk,
        len(threat_signals),
        severity_breakdown,
        property_breakdown,
        top_threats,
        has_uncertainty
    )
    
    # Collect all threat IDs
    threat_ids = [t.threat_id for t in threat_signals if hasattr(t, 'threat_id')]
    
    return DatasetRiskSummary(
        overall_risk_level=overall_risk,
        total_threats=len(threat_signals),
        severity_breakdown=severity_breakdown,
       property_breakdown=property_breakdown,
        top_threats=top_threats,
        escalation_reasons=escalation_reasons,
        summary_text=summary_text,
        threat_ids=threat_ids,
        confidence_stats=confidence_stats,
        total_missing_metrics=total_missing,
        has_uncertainty=has_uncertainty
    )


# ============================================================================
# INTERNAL HELPER FUNCTIONS (Pure Logic, No Side Effects)
# ============================================================================

def _determine_risk_level(threats: List[ThreatSignal]) -> tuple[str, List[str]]:
    """
    Determine overall risk level using deterministic escalation rules.
    
    Returns:
        Tuple of (risk_level, list_of_reasons)
    """
    # Evaluate rules in priority order: critical > warning > low
    for risk_level in ["critical", "warning", "low"]:
        for rule in ESCALATION_RULES[risk_level]:
            try:
                if rule["condition"](threats):
                    return risk_level, [rule["reason"]]
            except Exception as e:
                logger.warning(f"Error evaluating rule {rule['name']}: {e}")
                continue
    
    # Fallback (should never reach here if rules are comprehensive)
    return "warning", ["Unable to determine risk level (fallback)"]


def _rank_top_threats(threats: List[ThreatSignal], top_n: int) -> List[Dict[str, Any]]:
    """
    Rank threats by priority and return top N.
    
    Priority scoring:
    - Severity: high=3, medium=2, low=1
    - Property weight: privacy=3, utility=2, consistency=1
    - Confidence score
    
    Returns list of dicts with threat details.
    """
    severity_weight = {"high": 3, "medium": 2, "low": 1}
    property_weight = {"privacy": 3, "utility": 2, "consistency": 1}
    
    # Score each threat
    scored_threats = []
    for threat in threats:
        priority_score = (
            severity_weight.get(threat.severity, 1) * 10 +
            property_weight.get(threat.impacted_property, 1) * 5 +
            threat.confidence * 10
        )
        
        scored_threats.append({
            "threat_id": threat.threat_id,
            "threat_name": threat.threat_name,
            "severity": threat.severity,
            "impacted_property": threat.impacted_property,
            "confidence": threat.confidence,
            "priority_score": round(priority_score, 2),
            "triggered_by": threat.triggered_by[:2]  # First 2 conditions for brevity
        })
    
    # Sort by priority score (descending) and return top N
    scored_threats.sort(key=lambda x: x["priority_score"], reverse=True)
    return scored_threats[:top_n]


def _generate_summary_text(
    risk_level: str,
    total_threats: int,
    severity_breakdown: Dict[str, int],
    property_breakdown: Dict[str, int],
    top_threats: List[Dict[str, Any]],
    has_uncertainty: bool = False
) -> str:
    """
    Generate human-readable summary text.
    
    Returns concise, actionable summary string.
    """
    # Risk level introduction
    if risk_level == "critical":
        intro = "⚠️ CRITICAL RISK: Immediate review required."
    elif risk_level == "warning":
        intro = "⚡ WARNING: Elevated risk detected."
    else:
        intro = "✓ LOW RISK: Minor concerns detected."
    
    # Threat composition
    composition = (
        f"Detected {total_threats} threat(s): "
        f"{severity_breakdown['high']} high, "
        f"{severity_breakdown['medium']} medium, "
        f"{severity_breakdown['low']} low severity."
    )
    
    # Property impact
    privacy_impact = property_breakdown.get("privacy", 0)
    utility_impact = property_breakdown.get("utility", 0)
    
    if privacy_impact > 0:
        impact = f"Privacy concerns: {privacy_impact} threat(s)."
    elif utility_impact > 0:
        impact = f"Utility concerns: {utility_impact} threat(s)."
    else:
        impact = "Consistency concerns detected."
    
    # Top threat
    if top_threats:
        top_threat = top_threats[0]
        priority_note = f"Top priority: {top_threat['threat_name']} ({top_threat['severity']})."
    else:
        priority_note = ""
    
    # Uncertainty note
    uncertainty_note = ""
    if has_uncertainty:
        uncertainty_note = "[Note: Some metrics were missing/invalid]"
    
    # Combine into summary
    parts = [intro, composition, impact, priority_note, uncertainty_note]
    return " ".join(p for p in parts if p)


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_risk_level_description(risk_level: str) -> str:
    """Get human-readable description of risk level."""
    descriptions = {
        "critical": "Critical risk requiring immediate attention. Dataset may pose significant privacy or governance concerns.",
        "warning": "Elevated risk detected. Review recommended before deployment or sharing.",
        "low": "Low risk profile. Standard monitoring and governance practices apply."
    }
    return descriptions.get(risk_level, "Unknown risk level")


def explain_escalation_rules() -> Dict[str, List[str]]:
    """
    Return documentation of escalation rules for transparency.
    
    Returns:
        Dict mapping risk levels to list of rule descriptions
    """
    rules_doc = {}
    for risk_level, rules in ESCALATION_RULES.items():
        rules_doc[risk_level] = [rule["reason"] for rule in rules]
    return rules_doc


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "DatasetRiskSummary",
    "aggregate_dataset_threats",
    "get_risk_level_description",
    "explain_escalation_rules",
    "ESCALATION_RULES",
]
