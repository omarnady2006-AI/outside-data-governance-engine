"""
Public Core API for Outside Data Governance Engine

This module provides a clean, stable entry-point for evaluating governance risks
in synthetic datasets. It wraps the internal threat mapping and aggregation layers
with safe defaults and graceful error handling.

IMPORTANT: This engine is ADVISORY ONLY.
- It describes governance risks (privacy, utility, consistency)
- It does NOT make approve/reject decisions
- It does NOT enforce policies
- All outputs are informational for human review
"""

from typing import Dict, Any, Optional, List, Literal
from dataclasses import dataclass, field, asdict
from datetime import datetime
import logging

# Import internal layers (already implemented)
try:
    from .threat_mapping import map_metrics_to_threats, ThreatSignal
    from .threat_aggregation import aggregate_dataset_threats, DatasetRiskSummary
except ImportError:
    from threat_mapping import map_metrics_to_threats, ThreatSignal
    from threat_aggregation import aggregate_dataset_threats, DatasetRiskSummary

logger = logging.getLogger(__name__)

__version__ = "2.1.0"


@dataclass
class GovernanceResult:
    """
    Structured result from governance evaluation.
    
    This is the single output format for the public API. It contains:
    - dataset_risk_summary: Aggregated risk assessment
    - threats: Individual threat signals (optional, based on output_mode)
    - has_uncertainty: Whether evaluation had missing/invalid data
    - uncertainty_notes: Human-readable explanations of data quality issues
    - metadata: Version, timestamp, configuration used
    
    This result is ADVISORY ONLY. It does not contain approval decisions.
    """
    dataset_risk_summary: DatasetRiskSummary
    threats: Optional[List[ThreatSignal]] = None
    has_uncertainty: bool = False
    uncertainty_notes: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    disclaimers: List[str] = field(default_factory=lambda: [
        "This assessment is advisory only and does not constitute compliance certification",
        "Risk levels are interpretive and should inform, not replace, human decision-making",
        "No approval or rejection decisions are made by this system"
    ])
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for JSON serialization.
        
        Returns:
            Dictionary representation with all fields serialized.
        """
        result = {
            'dataset_risk_summary': self.dataset_risk_summary.to_dict() if self.dataset_risk_summary else None,
            'threats': [t.to_dict() for t in self.threats] if self.threats else None,
            'has_uncertainty': self.has_uncertainty,
            'uncertainty_notes': self.uncertainty_notes,
            'metadata': self.metadata,
            'disclaimers': self.disclaimers
        }
        return result


def evaluate_governance(
    metrics: Dict[str, Any],
    output_mode: Literal["summary", "detailed", "full"] = "summary",
    config: Optional[Dict[str, Any]] = None,
    strict_mode: bool = False
) -> GovernanceResult:
    """
    Evaluate governance risks for a synthetic dataset.
    
    This is the primary public API entry-point for the Outside Data Governance Engine.
    It analyzes metrics from a synthetic dataset evaluation and returns a structured
    risk assessment.
    
    WHAT THIS FUNCTION DOES:
    - Maps metrics to specific privacy/utility/consistency threats
    - Aggregates threats into dataset-level risk summary
    - Provides human-readable risk descriptions
    - Handles edge cases gracefully (missing data, invalid values)
    
    WHAT THIS FUNCTION DOES NOT DO:
    - Make approve/reject decisions (advisory only)
    - Enforce policies or gate deployments
    - Modify or validate the input dataset
    - Interact with external services or LLMs
    
    Args:
        metrics: Dictionary of evaluation metrics, typically from RuleEngine.
                Expected keys include:
                - privacy_score (float 0-1)
                - utility_score (float 0-1)
                - privacy_risk (dict with membership_inference_auc, etc.)
                - statistical_fidelity (dict with KL divergence, etc.)
                - semantic_invariants (dict with violation counts)
                
                Empty or partial metrics are handled gracefully.
        
        output_mode: Controls level of detail in response:
                - "summary": Risk summary only (fast, minimal)
                - "detailed": Includes individual threat signals
                - "full": Everything including detailed metadata
                Default: "summary"
        
        config: Optional configuration overrides. Currently supported:
                - top_threats_count (int): Number of top threats to include
                Default: {"top_threats_count": 5}
        
        strict_mode: If True, re-raise exceptions after logging (for development/testing).
                    If False (default), return graceful fallback results.
                    Default: False
    
    Returns:
        GovernanceResult: Structured result with risk assessment.
        
        Always returns a valid result, even on empty input or errors.
        Check `has_uncertainty` flag for data quality issues.
    
    Raises:
        Never raises exceptions. All errors are captured and returned
        in the result with uncertainty flags.
    
    Example:
        >>> metrics = {
        ...     "privacy_score": 0.85,
        ...     "utility_score": 0.90,
        ...     "privacy_risk": {"membership_inference_auc": 0.52}
        ... }
        >>> result = evaluate_governance(metrics)
        >>> print(result.dataset_risk_summary.overall_risk_level)
        'low'
        
        >>> # With detailed threats
        >>> result = evaluate_governance(metrics, output_mode="detailed")
        >>> for threat in result.threats:
        ...     print(f"{threat.threat_name}: {threat.severity}")
        
        >>> # Handle empty input safely
        >>> result = evaluate_governance({})
        >>> print(result.has_uncertainty)
        True
    """
    # Apply default config
    if config is None:
        config = {}
    
    top_threats_count = config.get('top_threats_count', 5)
    
    # Initialize result components
    uncertainty_notes = []
    has_uncertainty = False
    threats = []
    dataset_risk_summary = None
    
    # Metadata
    metadata = {
        'engine_version': __version__,
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'output_mode': output_mode,
        'config': config
    }
    
    try:
        # Validate input
        if not metrics or not isinstance(metrics, dict):
            has_uncertainty = True
            uncertainty_notes.append("No metrics provided or invalid input format")
            logger.warning("evaluate_governance called with empty or invalid metrics")
            
            # Create empty risk summary for graceful degradation
            from .threat_aggregation import DatasetRiskSummary
            dataset_risk_summary = DatasetRiskSummary(
                overall_risk_level="unknown",
                total_threats=0,
                severity_breakdown={'high': 0, 'medium': 0, 'low': 0},
                property_breakdown={'privacy': 0, 'utility': 0, 'consistency': 0},
                top_threats=[],
                escalation_reasons=["No metrics available for evaluation"],
                summary_text="Cannot evaluate: no metrics provided",
                threat_ids=[],
                confidence_stats={'avg': 0.0, 'max': 0.0, 'min': 0.0}
            )
        else:
            # Step 1: Map metrics to threat signals
            try:
                # Use internal threat mapping layer
                threat_output_mode = "detailed"  # Always get detailed for aggregation
                threats = map_metrics_to_threats(metrics, output_mode=threat_output_mode)
                
                if not threats:
                    has_uncertainty = True
                    uncertainty_notes.append("No threats detected - metrics may be incomplete")
                    
            except Exception as e:
                has_uncertainty = True
                uncertainty_notes.append(f"Threat mapping failed: {str(e)}")
                logger.error(f"Threat mapping error: {e}", exc_info=True)
                threats = []
            
            # Step 2: Aggregate to dataset-level risk summary
            try:
                if threats:
                    dataset_risk_summary = aggregate_dataset_threats(
                        threats,
                        top_n=top_threats_count
                    )
                else:
                    # Create minimal summary for zero threats
                    from .threat_aggregation import DatasetRiskSummary
                    dataset_risk_summary = DatasetRiskSummary(
                        overall_risk_level="low",
                        total_threats=0,
                        severity_breakdown={'high': 0, 'medium': 0, 'low': 0},
                        property_breakdown={'privacy': 0, 'utility': 0, 'consistency': 0},
                        top_threats=[],
                        escalation_reasons=[],
                        summary_text="No threats detected in provided metrics",
                        threat_ids=[],
                        confidence_stats={'avg': 0.0, 'max': 0.0, 'min': 0.0}
                    )
                    
            except Exception as e:
                has_uncertainty = True
                uncertainty_notes.append(f"Threat aggregation failed: {str(e)}")
                logger.error(f"Threat aggregation error: {e}", exc_info=True)
                
                # Fallback summary
                from .threat_aggregation import DatasetRiskSummary
                dataset_risk_summary = DatasetRiskSummary(
                    overall_risk_level="unknown",
                    total_threats=len(threats),
                    severity_breakdown={'high': 0, 'medium': 0, 'low': 0},
                    property_breakdown={'privacy': 0, 'utility': 0, 'consistency': 0},
                    top_threats=[],
                    escalation_reasons=["Aggregation failed - see uncertainty notes"],
                    summary_text="Risk assessment incomplete due to processing error",
                    threat_ids=[],
                    confidence_stats={'avg': 0.0, 'max': 0.0, 'min': 0.0}
                )
        
        # Determine what to include based on output_mode
        include_threats = None
        if output_mode == "detailed" or output_mode == "full":
            include_threats = threats
        
        # Add uncertainty from internal layers if present
        if dataset_risk_summary and hasattr(dataset_risk_summary, 'has_uncertainty'):
            # Check if any threat has uncertainty
            for threat in threats:
                if threat.missing_metrics > 0:
                    has_uncertainty = True
                    uncertainty_notes.append(
                        f"Threat '{threat.threat_name}' has {threat.missing_metrics} missing metrics"
                    )
                if threat.uncertainty_notes:
                    has_uncertainty = True
                    uncertainty_notes.extend(threat.uncertainty_notes)
        
        # Build final result
        result = GovernanceResult(
            dataset_risk_summary=dataset_risk_summary,
            threats=include_threats,
            has_uncertainty=has_uncertainty,
            uncertainty_notes=uncertainty_notes,
            metadata=metadata
        )
        
        return result
        
    except Exception as e:
        # Ultimate safety net - should never reach here
        logger.critical(f"Unexpected error in evaluate_governance: {e}", exc_info=True)
        
        if strict_mode:
            raise  # Re-raise for development/testing
        
        # Return minimal safe result
        from .threat_aggregation import DatasetRiskSummary
        fallback_summary = DatasetRiskSummary(
            overall_risk_level="unknown",
            total_threats=0,
            severity_breakdown={'high': 0, 'medium': 0, 'low': 0},
            property_breakdown={'privacy': 0, 'utility': 0, 'consistency': 0},
            top_threats=[],
            escalation_reasons=["Critical error during evaluation"],
            summary_text=f"Evaluation failed: {str(e)}",
            threat_ids=[],
            confidence_stats={'avg': 0.0, 'max': 0.0, 'min': 0.0}
        )
        
        return GovernanceResult(
            dataset_risk_summary=fallback_summary,
            threats=None,
            has_uncertainty=True,
            uncertainty_notes=[f"Critical evaluation error: {str(e)}"],
            metadata=metadata
        )


__all__ = [
    'evaluate_governance',
    'GovernanceResult',
    '__version__'
]
