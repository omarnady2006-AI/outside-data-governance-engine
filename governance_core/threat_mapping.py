"""
Threat-Driven Metrics Mapping

This module provides a declarative mapping between existing metrics and explicit
privacy and governance threats. It is purely interpretive and structural - it does
NOT change how metrics are computed or introduce pipeline decisions.

Purpose:
- Link metrics to specific attack types
- Identify impacted properties (privacy/utility/consistency)
- Provide severity assessments for governance interpretation
- Enable threat-based auditability

Constraints:
- This is metadata only - no computation logic
- All mappings reference existing metric names
- No APPROVE/REJECT logic - advisory only
- Backward-compatible with existing system
"""

from typing import Dict, List, Optional, Any, Literal
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)


# ============================================================================
# STABLE THREAT IDENTIFIERS
# ============================================================================
# Constants for deterministic, human-readable threat IDs

THREAT_MEMBERSHIP_INFERENCE = "membership_inference"
THREAT_RECORD_LINKAGE = "record_linkage"
THREAT_ATTRIBUTE_INFERENCE = "attribute_inference"
THREAT_PRIVACY_LEAKAGE = "privacy_leakage"
THREAT_SEMANTIC_VIOLATION = "semantic_violation"
THREAT_DISTRIBUTION_DRIFT = "distribution_drift"
THREAT_CORRELATION_INCONSISTENCY = "correlation_inconsistency"
THREAT_UTILITY_DEGRADATION = "utility_degradation"


@dataclass
class ThreatSignal:
    """
    Represents a detected threat signal derived from metrics.
    
    Attributes:
        threat_id: Stable unique identifier (use THREAT_* constants)
        threat_name: Human-readable threat name
        attack_type: Type of attack (e.g., membership_inference, attribute_inference)
        impacted_property: Which property is at risk (privacy/utility/consistency)
        severity: Derived severity level (low/medium/high)
        confidence: Confidence score (0.0-1.0) based on metric distance from threshold
        related_metrics: List of metric names that triggered this threat
        metric_values: Dictionary of relevant metric values (for context only)
        triggered_by: List of human-readable conditions that triggered this threat
        description: Human-readable description of the threat
        missing_metrics: Number of expected metrics that were missing/invalid
        uncertainty_notes: List of issues encountered during threat detection
    """
    threat_id: str
    threat_name: str
    attack_type: str
    impacted_property: str  # privacy | utility | consistency
    severity: str  # low | medium | high
    confidence: float  # 0.0 - 1.0, strength of evidence
    related_metrics: List[str]
    metric_values: Dict[str, Any]
    triggered_by: List[str]  # Explicit rule conditions that triggered detection
    description: str
    missing_metrics: int = 0  # Count of expected but missing/invalid metrics
    uncertainty_notes: List[str] = None  # Issues encountered (e.g., "NaN values")
    
    def __post_init__(self):
        """Initialize uncertainty_notes as empty list if None."""
        if self.uncertainty_notes is None:
            self.uncertainty_notes = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


# ============================================================================
# THREAT CATALOG
# ============================================================================
# Static, declarative mapping of threats to metrics and severity rules.
# This is the single source of truth for threat interpretation.
# ============================================================================

THREAT_CATALOG = {
    THREAT_MEMBERSHIP_INFERENCE: {
        "threat_name": "Membership Inference Attack",
        "attack_type": "membership_inference",
        "impacted_property": "privacy",
        "description": (
            "An attacker could determine whether a specific record was part of the "
            "original training dataset by analyzing synthetic data characteristics."
        ),
        "metrics": [
            "membership_inference_auc",
            "membership_inference_accuracy"
        ],
        "severity_rules": {
            # Rules evaluated in order; first match wins
            "high": lambda m: m.get("membership_inference_auc", 0) > 0.70,
            "medium": lambda m: m.get("membership_inference_auc", 0) > 0.60,
            "low": lambda m: m.get("membership_inference_auc", 0) <= 0.60,
        },
        "thresholds": {
            "high": 0.70,
            "medium": 0.60,
            "baseline": 0.50  # Random guessing baseline
        }
    },
    
    THREAT_RECORD_LINKAGE: {
        "threat_name": "Record Linkage / Re-identification",
        "attack_type": "record_linkage",
        "impacted_property": "privacy",
        "description": (
            "Near-duplicate records or exact matches could enable linking synthetic "
            "records back to original individuals, especially when combined with "
            "external datasets containing quasi-identifiers."
        ),
        "metrics": [
            "near_duplicates_count",
            "near_duplicates_rate",
            "min_nn_distance"
        ],
        "severity_rules": {
            "high": lambda m: (
                m.get("near_duplicates_rate", 0) > 0.02 or 
                m.get("near_duplicates_count", 0) > 10
            ),
            "medium": lambda m: (
                m.get("near_duplicates_rate", 0) > 0.01 or
                m.get("min_nn_distance", float('inf')) < 0.5
            ),
            "low": lambda m: m.get("near_duplicates_rate", 0) <= 0.01,
        },
        "thresholds": {
            "high_rate": 0.02,
            "high_count": 10,
            "medium_rate": 0.01,
            "min_distance": 0.5
        }
    },
    
    THREAT_ATTRIBUTE_INFERENCE: {
        "threat_name": "Attribute Inference Attack",
        "attack_type": "attribute_inference",
        "impacted_property": "privacy",
        "description": (
            "Strong correlations in synthetic data could allow attackers to infer "
            "sensitive attributes from known quasi-identifiers with high accuracy."
        ),
        "metrics": [
            "attribute_inference_accuracy",
            "correlation_frobenius_norm"
        ],
        "severity_rules": {
            "high": lambda m: m.get("attribute_inference_accuracy", 0) > 0.85,
            "medium": lambda m: m.get("attribute_inference_accuracy", 0) > 0.75,
            "low": lambda m: m.get("attribute_inference_accuracy", 0) <= 0.75,
        },
        "thresholds": {
            "high": 0.85,
            "medium": 0.75,
            "baseline": 0.50
        }
    },
    
    THREAT_PRIVACY_LEAKAGE: {
        "threat_name": "General Privacy Leakage",
        "attack_type": "privacy_leakage",
        "impacted_property": "privacy",
        "description": (
            "Overall privacy score indicates potential information leakage through "
            "various channels including record similarity, membership patterns, and "
            "nearest-neighbor proximity."
        ),
        "metrics": [
            "privacy_score",
            "leakage_risk_level",
            "avg_nn_distance"
        ],
        "severity_rules": {
            "high": lambda m: m.get("privacy_score", 1.0) < 0.60,
            "medium": lambda m: m.get("privacy_score", 1.0) < 0.80,
            "low": lambda m: m.get("privacy_score", 1.0) >= 0.80,
        },
        "thresholds": {
            "high": 0.60,
            "medium": 0.80,
            "baseline": 1.0
        }
    },
    
    THREAT_SEMANTIC_VIOLATION: {
        "threat_name": "Semantic Constraint Violation",
        "attack_type": "semantic_violation",
        "impacted_property": "consistency",
        "description": (
            "Violations of domain-specific business rules or cross-field constraints "
            "indicate synthetic data may not respect real-world invariants, potentially "
            "revealing generation artifacts or enabling detection."
        ),
        "metrics": [
            "semantic_violations",
            "field_constraint_violations",
            "cross_field_violations"
        ],
        "severity_rules": {
            "high": lambda m: m.get("semantic_violations", 0) > 100,
            "medium": lambda m: m.get("semantic_violations", 0) > 10,
            "low": lambda m: m.get("semantic_violations", 0) > 0,
        },
        "thresholds": {
            "high": 100,
            "medium": 10,
            "baseline": 0
        }
    },
    
    THREAT_DISTRIBUTION_DRIFT: {
        "threat_name": "Statistical Distribution Drift",
        "attack_type": "distribution_drift",
        "impacted_property": "utility",
        "description": (
            "Significant divergence in statistical distributions could compromise "
            "the utility of synthetic data for downstream ML tasks and reduce "
            "the fidelity of insights derived from it."
        ),
        "metrics": [
            "statistical_drift",
            "avg_kl_divergence",
            "avg_wasserstein_distance",
            "avg_psi"
        ],
        "severity_rules": {
            "high": lambda m: (
                m.get("statistical_drift", "").lower() == "high" or
                m.get("avg_kl_divergence", 0) > 0.5
            ),
            "medium": lambda m: (
                m.get("statistical_drift", "").lower() == "moderate" or
                m.get("avg_kl_divergence", 0) > 0.2
            ),
            "low": lambda m: m.get("statistical_drift", "").lower() in ["low", "none"],
        },
        "thresholds": {
            "high_kl": 0.5,
            "medium_kl": 0.2,
            "baseline": 0.0
        }
    },
    
    THREAT_CORRELATION_INCONSISTENCY: {
        "threat_name": "Correlation Structure Inconsistency",
        "attack_type": "correlation_inconsistency",
        "impacted_property": "utility",
        "description": (
            "Divergence in correlation patterns between synthetic and original data "
            "can compromise model performance and analytical validity, especially "
            "for multivariate analyses."
        ),
        "metrics": [
            "correlation_frobenius_norm",
            "feature_importance_correlation"
        ],
        "severity_rules": {
            "high": lambda m: m.get("correlation_frobenius_norm", 0) > 2.0,
            "medium": lambda m: m.get("correlation_frobenius_norm", 0) > 1.0,
            "low": lambda m: m.get("correlation_frobenius_norm", 0) <= 1.0,
        },
        "thresholds": {
            "high": 2.0,
            "medium": 1.0,
            "baseline": 0.0
        }
    },
    
    THREAT_UTILITY_DEGRADATION: {
        "threat_name": "ML Utility Degradation",
        "attack_type": "utility_degradation",
        "impacted_property": "utility",
        "description": (
            "Reduced utility score indicates that models trained on synthetic data "
            "significantly underperform compared to models trained on real data, "
            "limiting the value of the synthetic dataset for ML applications."
        ),
        "metrics": [
            "utility_score",
            "utility_assessment",
            "synthetic_model_accuracy",
            "accuracy_gap"
        ],
        "severity_rules": {
            "high": lambda m: m.get("utility_score", 1.0) < 0.70,
            "medium": lambda m: m.get("utility_score", 1.0) < 0.85,
            "low": lambda m: m.get("utility_score", 1.0) >= 0.85,
        },
        "thresholds": {
            "high": 0.70,
            "medium": 0.85,
            "baseline": 1.0
        }
    },
}


# ============================================================================
# CORE API FUNCTIONS
# ============================================================================

def map_metrics_to_threats(
    metrics_dict: Dict[str, Any],
    output_mode: Literal["summary", "detailed", "json"] = "detailed"
) -> Any:
    """
    Map evaluation metrics to threat signals.
    
    This function analyzes the provided metrics dictionary and identifies which
    threats are present based on the declarative THREAT_CATALOG mapping.
    
    Args:
        metrics_dict: Complete metrics dictionary from evaluation
        output_mode: Output format control:
            - "summary": Returns summary dict with counts only
            - "detailed": Returns full list of ThreatSignal objects (default)
            - "json": Returns JSON-serializable dict (no objects)
    
    Returns:
        Depends on output_mode:
        - "summary": Dict with severity/property counts
        - "detailed": List[ThreatSignal]
        - "json": Dict with serializable threat data
        
    Example:
        >>> metrics = {"privacy_score": 0.75}
        >>> threats = map_metrics_to_threats(metrics, output_mode="detailed")
        >>> summary = map_metrics_to_threats(metrics, output_mode="summary")
    """
    # Always compute full threat signals first
    threat_signals = _compute_threat_signals(metrics_dict)
    
    # Return based on requested mode
    if output_mode == "summary":
        return get_threat_summary(threat_signals)
    elif output_mode == "json":
        return {
            "threats": [signal.to_dict() for signal in threat_signals],
            "summary": get_threat_summary(threat_signals)
        }
    else:  # detailed (default)
        return threat_signals


def get_threat_summary(threat_signals: List[ThreatSignal]) -> Dict[str, Any]:
    """
    Generate a summary of detected threats grouped by severity and property.
    
    Args:
        threat_signals: List of ThreatSignal objects
        
    Returns:
        Dictionary with threat summary statistics and groupings
    """
    summary = {
        "total_threats": len(threat_signals),
        "by_severity": {"high": [], "medium": [], "low": []},
        "by_property": {"privacy": [], "utility": [], "consistency": []},
        "threat_ids": [t.threat_id for t in threat_signals]
    }
    
    for signal in threat_signals:
        summary["by_severity"][signal.severity].append(signal.threat_id)
        summary["by_property"][signal.impacted_property].append(signal.threat_id)
    
    summary["severity_counts"] = {
        "high": len(summary["by_severity"]["high"]),
        "medium": len(summary["by_severity"]["medium"]),
        "low": len(summary["by_severity"]["low"])
    }
    
    summary["property_counts"] = {
        "privacy": len(summary["by_property"]["privacy"]),
        "utility": len(summary["by_property"]["utility"]),
        "consistency": len(summary["by_property"]["consistency"])
    }
    
    return summary


def get_threat_by_id(threat_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve threat definition from catalog by ID."""
    return THREAT_CATALOG.get(threat_id)


def list_all_threats() -> List[str]:
    """Get list of all threat IDs defined in the catalog."""
    return list(THREAT_CATALOG.keys())


def get_metrics_for_threat(threat_id: str) -> Optional[List[str]]:
    """Get list of metrics associated with a specific threat."""
    threat_config = THREAT_CATALOG.get(threat_id)
    return threat_config["metrics"] if threat_config else None


# ============================================================================
# INTERNAL FUNCTIONS (NO PRINTING - PURE LOGIC)
# ============================================================================

def _compute_threat_signals(metrics_dict: Dict[str, Any]) -> List[ThreatSignal]:
    """
    Core threat detection logic. Returns data only, no side effects.
    Handles edge cases: None inputs, missing keys, NaN/inf values.
    """
    # Edge case: None or empty input
    if metrics_dict is None:
        logger.warning("Received None metrics_dict, returning empty threat list")
        return []
    
    if not isinstance(metrics_dict, dict):
        logger.warning(f"Expected dict, got {type(metrics_dict)}, returning empty threat list")
        return []
    
    threat_signals = []
    flat_metrics = _flatten_metrics(metrics_dict)
    
    # Sanitize flat metrics: remove None/NaN/inf values
    flat_metrics = _sanitize_metrics(flat_metrics)
    
    for threat_id, threat_config in THREAT_CATALOG.items():
        # Track uncertainty for this threat
        uncertainty_notes = []
        expected_metrics = threat_config["metrics"]
        
        # Check if any threat metrics are present and valid
        relevant_metrics = {}
        missing_count = 0
        
        for metric_name in expected_metrics:
            if metric_name in flat_metrics:
                value = flat_metrics[metric_name]
                if _is_valid_metric_value(value):
                    relevant_metrics[metric_name] = value
                else:
                    missing_count += 1
                    uncertainty_notes.append(f"Invalid value for {metric_name}")
            else:
                missing_count += 1
        
        # Skip if no valid metrics present
        if not relevant_metrics:
            continue
        
        # Try to evaluate severity with error handling
        try:
            severity = _evaluate_severity(flat_metrics, threat_config["severity_rules"])
        except Exception as e:
            logger.warning(f"Error evaluating severity for {threat_id}: {e}")
            uncertainty_notes.append(f"Severity evaluation failed: {str(e)[:50]}")
            severity = None
        
        if not severity:
            continue
        
        # Compute confidence score with error handling
        try:
            confidence = _compute_confidence(flat_metrics, threat_config, severity)
        except Exception as e:
            logger.warning(f"Error computing confidence for {threat_id}: {e}")
            confidence = 0.5  # Default medium confidence on error
            uncertainty_notes.append("Confidence calculation failed")
        
        # Determine what triggered this threat
        try:
            triggered_by = _explain_trigger_conditions(flat_metrics, threat_config, severity)
        except Exception as e:
            logger.warning(f"Error explaining triggers for {threat_id}: {e}")
            triggered_by = ["Triggered by threshold (details unavailable)"]
            uncertainty_notes.append("Trigger explanation failed")
        
        signal = ThreatSignal(
            threat_id=threat_id,
            threat_name=threat_config["threat_name"],
            attack_type=threat_config["attack_type"],
            impacted_property=threat_config["impacted_property"],
            severity=severity,
            confidence=confidence,
            related_metrics=list(relevant_metrics.keys()),
            metric_values=relevant_metrics,
            triggered_by=triggered_by,
            description=threat_config["description"],
            missing_metrics=missing_count,
            uncertainty_notes=uncertainty_notes
        )
        threat_signals.append(signal)
    
    return threat_signals


def _flatten_metrics(metrics_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Flatten nested metrics for easier lookup.
    Handles edge cases: skips non-dict values gracefully.
    """
    flat = {}
    
    if not metrics_dict:
        return flat
    
    try:
        for key, value in metrics_dict.items():
            # Add top-level key (even if None/invalid)
            flat[key] = value
            
            # Safely flatten nested dicts
            if isinstance(value, dict):
                try:
                    for nested_key, nested_value in value.items():
                        flat[nested_key] = nested_value
                except (AttributeError, TypeError) as e:
                    logger.debug(f"Skipping malformed nested dict at {key}: {e}")
                    continue
    except (AttributeError, TypeError) as e:
        logger.warning(f"Error flattening metrics: {e}")
    
    return flat


def _is_valid_metric_value(value: Any) -> bool:
    """
    Check if a metric value is valid (not None, NaN, or inf).
    
    Returns:
        True if value is valid and usable, False otherwise
    """
    if value is None:
        return False
    
    # Check for numeric NaN/inf
    if isinstance(value, (int, float)):
        import math
        if math.isnan(value) or math.isinf(value):
            return False
    
    # String metrics are valid if not empty
    if isinstance(value, str) and not value.strip():
        return False
    
    return True


def _sanitize_metrics(metrics: Dict[str, Any]) -> Dict[str, Any]:
    """
    Remove invalid metric values from dictionary.
    Replaces NaN/inf with None, which will then be filtered out.
    
    Args:
        metrics: Flattened metrics dictionary
        
    Returns:
        Dictionary with only valid metric values
    """
    sanitized = {}
    import math
    
    for key, value in metrics.items():
        # Skip if explicitly None
        if value is None:
            continue
        
        # Check numeric values for NaN/inf
        if isinstance(value, (int, float)):
            if math.isnan(value) or math.isinf(value):
                logger.debug(f"Skipping invalid numeric value for {key}: {value}")
                continue
        
        # Keep valid values
        sanitized[key] = value
    
    return sanitized


def _evaluate_severity(
    metrics: Dict[str, Any],
    severity_rules: Dict[str, callable]
) -> Optional[str]:
    """Evaluate severity based on rules (high > medium > low priority)."""
    for severity in ["high", "medium", "low"]:
        if severity in severity_rules:
            try:
                if severity_rules[severity](metrics):
                    return severity
            except Exception as e:
                logger.warning(f"Error evaluating severity rule for {severity}: {e}")
    return None


def _compute_confidence(
    metrics: Dict[str, Any],
    threat_config: Dict[str, Any],
    severity: str
) -> float:
    """
    Compute confidence score (0.0-1.0) based on metric distance from thresholds.
    
    Confidence reflects strength of evidence for the threat.
    Higher values = stronger evidence, clearer threat signal.
    """
    threat_id = threat_config.get("attack_type", "")
    thresholds = threat_config.get("thresholds", {})
    
    # Threat-specific confidence calculations
    if threat_id == "membership_inference":
        auc = metrics.get("membership_inference_auc", 0.5)
        baseline = thresholds.get("baseline", 0.5)
        # Distance from random guessing (0.5)
        distance = abs(auc - baseline)
        confidence = min(distance * 2.0, 1.0)  # Scale to 0-1
        
    elif threat_id == "record_linkage":
        dup_rate = metrics.get("near_duplicates_rate", 0)
        # Higher rate = higher confidence
        confidence = min(dup_rate * 50.0, 1.0)
        
    elif threat_id == "privacy_leakage":
        score = metrics.get("privacy_score", 1.0)
        baseline = thresholds.get("baseline", 1.0)
        # Distance from perfect privacy (1.0)
        distance = baseline - score
        confidence = min(distance / 0.4, 1.0)
        
    elif threat_id == "semantic_violation":
        violations = metrics.get("semantic_violations", 0)
        # Logarithmic scale for violations
        if violations == 0:
            confidence = 0.0
        else:
            import math
            confidence = min(math.log10(violations + 1) / 3.0, 1.0)
            
    elif threat_id == "distribution_drift":
        kl_div = metrics.get("avg_kl_divergence", 0)
        # Scale KL divergence to confidence
        confidence = min(kl_div / 1.0, 1.0)
        
    elif threat_id in ["utility_degradation", "correlation_inconsistency", "attribute_inference"]:
        # Generic approach for utility metrics
        # Use severity as proxy
        confidence = {"low": 0.3, "medium": 0.6, "high": 0.9}.get(severity, 0.5)
        
    else:
        # Fallback: use severity as confidence indicator
        confidence = {"low": 0.4, "medium": 0.7, "high": 0.9}.get(severity, 0.5)
    
    return round(confidence, 3)


def _explain_trigger_conditions(
    metrics: Dict[str, Any],
    threat_config: Dict[str, Any],
    severity: str
) -> List[str]:
    """
    Generate human-readable explanations of what triggered this threat.
    
    Returns list of condition strings for auditability.
    """
    conditions = []
    threat_id = threat_config.get("attack_type", "")
    thresholds = threat_config.get("thresholds", {})
    
    # Threat-specific condition explanations
    if threat_id == "membership_inference":
        auc = metrics.get("membership_inference_auc")
        if auc is not None:
            if severity == "high":
                conditions.append(f"membership_inference_auc ({auc:.3f}) > 0.70")
            elif severity == "medium":
                conditions.append(f"membership_inference_auc ({auc:.3f}) > 0.60")
            else:
                conditions.append(f"membership_inference_auc ({auc:.3f}) detected")
                
    elif threat_id == "record_linkage":
        rate = metrics.get("near_duplicates_rate")
        count = metrics.get("near_duplicates_count")
        distance = metrics.get("min_nn_distance")
        
        if rate is not None and rate > 0.01:
            conditions.append(f"near_duplicates_rate ({rate:.4f}) > threshold")
        if count is not None and count > 5:
            conditions.append(f"near_duplicates_count ({count}) detected")
        if distance is not None and distance < 1.0:
            conditions.append(f"min_nn_distance ({distance:.2f}) < 1.0")
            
    elif threat_id == "privacy_leakage":
        score = metrics.get("privacy_score")
        if score is not None:
            if severity == "high":
                conditions.append(f"privacy_score ({score:.3f}) < 0.60")
            elif severity == "medium":
                conditions.append(f"privacy_score ({score:.3f}) < 0.80")
            else:
                conditions.append(f"privacy_score ({score:.3f}) below optimal")
                
    elif threat_id == "semantic_violation":
        violations = metrics.get("semantic_violations", 0)
        if violations > 0:
            conditions.append(f"semantic_violations ({violations}) detected")
        field_violations = metrics.get("field_constraint_violations", {})
        if field_violations:
            for field, count in field_violations.items():
                if count > 0:
                    conditions.append(f"{field}: {count} violations")
                    
    elif threat_id == "distribution_drift":
        drift = metrics.get("statistical_drift", "")
        kl_div = metrics.get("avg_kl_divergence")
        
        if drift.lower() in ["high", "moderate"]:
            conditions.append(f"statistical_drift = {drift}")
        if kl_div is not None and kl_div > 0.1:
            conditions.append(f"avg_kl_divergence ({kl_div:.3f}) > baseline")
            
    elif threat_id == "correlation_inconsistency":
        corr_diff = metrics.get("correlation_frobenius_norm")
        if corr_diff is not None:
            if severity == "high":
                conditions.append(f"correlation_frobenius_norm ({corr_diff:.2f}) > 2.0")
            elif severity == "medium":
                conditions.append(f"correlation_frobenius_norm ({corr_diff:.2f}) > 1.0")
            else:
                conditions.append(f"correlation_frobenius_norm ({corr_diff:.2f}) detected")
                
    elif threat_id == "utility_degradation":
        util_score = metrics.get("utility_score")
        if util_score is not None:
            if severity == "high":
                conditions.append(f"utility_score ({util_score:.3f}) < 0.70")
            elif severity == "medium":
                conditions.append(f"utility_score ({util_score:.3f}) < 0.85")
            else:
                conditions.append(f"utility_score ({util_score:.3f}) below optimal")
                
    elif threat_id == "attribute_inference":
        acc = metrics.get("attribute_inference_accuracy")
        if acc is not None:
            if severity == "high":
                conditions.append(f"attribute_inference_accuracy ({acc:.3f}) > 0.85")
            elif severity == "medium":
                conditions.append(f"attribute_inference_accuracy ({acc:.3f}) > 0.75")
    
    # Fallback if no conditions generated
    if not conditions:
        conditions.append(f"Detected based on {severity} severity threshold")
    
    return conditions


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Threat ID Constants
    "THREAT_MEMBERSHIP_INFERENCE",
    "THREAT_RECORD_LINKAGE",
    "THREAT_ATTRIBUTE_INFERENCE",
    "THREAT_PRIVACY_LEAKAGE",
    "THREAT_SEMANTIC_VIOLATION",
    "THREAT_DISTRIBUTION_DRIFT",
    "THREAT_CORRELATION_INCONSISTENCY",
    "THREAT_UTILITY_DEGRADATION",
    # Classes
    "ThreatSignal",
    # Core Functions
    "map_metrics_to_threats",
    "get_threat_summary",
    # Utilities
    "get_threat_by_id",
    "list_all_threats",
    "get_metrics_for_threat",
    # Catalog
    "THREAT_CATALOG",
]
