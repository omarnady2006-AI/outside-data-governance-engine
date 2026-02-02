"""
Example: Dataset-Level Threat Aggregation

Demonstrates how to aggregate individual threat signals into a
comprehensive dataset-level risk summary.

Shows:
- Risk level escalation (low/warning/critical)
- Threat prioritization and ranking
- Human-readable summaries
- Integration with existing threat mapping
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from governance_core.threat_mapping import map_metrics_to_threats
from governance_core.threat_aggregation import (
    aggregate_dataset_threats,
    get_risk_level_description,
    explain_escalation_rules
)


def example_metrics_low_risk():
    """Metrics that should produce low risk."""
    return {
        "privacy_score": 0.92,
        "utility_score": 0.95,
        "semantic_violations": 2,
        "statistical_drift": "low",
        "privacy_risk": {
            "membership_inference_auc": 0.52,
            "near_duplicates_rate": 0.001
        }
    }


def example_metrics_warning():
    """Metrics that should produce warning level."""
    return {
        "privacy_score": 0.72,
        "utility_score": 0.88,
        "semantic_violations": 3,
        "statistical_drift": "moderate",
        "privacy_risk": {
            "membership_inference_auc": 0.65,
            "near_duplicates_rate": 0.015
        },
        "statistical_fidelity": {
            "correlation_frobenius_norm": 1.5,
            "avg_kl_divergence": 0.25
        }
    }


def example_metrics_critical():
    """Metrics that should produce critical risk."""
    return {
        "privacy_score": 0.55,
        "utility_score": 0.65,
        "semantic_violations": 150,
        "statistical_drift": "high",
        "privacy_risk": {
            "membership_inference_auc": 0.78,
            "near_duplicates_rate": 0.035,
            "near_duplicates_count": 25
        },
        "statistical_fidelity": {
            "correlation_frobenius_norm": 2.8,
            "avg_kl_divergence": 0.65
        }
    }


def demo_aggregation_levels():
    """Demonstrate aggregation at different risk levels."""
    print("=" * 80)
    print("DATASET-LEVEL THREAT AGGREGATION")
    print("=" * 80)
    print()
    
    scenarios = [
        ("Low Risk Dataset", example_metrics_low_risk()),
        ("Warning Level Dataset", example_metrics_warning()),
        ("Critical Risk Dataset", example_metrics_critical())
    ]
    
    for scenario_name, metrics in scenarios:
        print(f"[ Scenario: {scenario_name} ]")
        print("-" * 80)
        
        # Step 1: Map metrics to threats (existing layer)
        threats = map_metrics_to_threats(metrics, output_mode="detailed")
        
        # Step 2: Aggregate threats to dataset level (NEW layer)
        summary = aggregate_dataset_threats(threats)
        
        # Display results
        print(f"Overall Risk Level: {summary.overall_risk_level.upper()}")
        print(f"Total Threats: {summary.total_threats}")
        print()
        
        print("Severity Breakdown:")
        print(f"  High:   {summary.severity_breakdown['high']}")
        print(f"  Medium: {summary.severity_breakdown['medium']}")
        print(f"  Low:    {summary.severity_breakdown['low']}")
        print()
        
        print("Property Impact:")
        print(f"  Privacy:     {summary.property_breakdown['privacy']}")
        print(f"  Utility:     {summary.property_breakdown['utility']}")
        print(f"  Consistency: {summary.property_breakdown['consistency']}")
        print()
        
        print("Confidence Stats:")
        print(f"  Average: {summary.confidence_stats['avg']:.3f}")
        print(f"  Max:     {summary.confidence_stats['max']:.3f}")
        print(f"  Min:     {summary.confidence_stats['min']:.3f}")
        print()
        
        print("Escalation Reason:")
        for reason in summary.escalation_reasons:
            print(f"  → {reason}")
        print()
        
        print("Summary:")
        print(f"  {summary.summary_text}")
        print()
        
        if summary.top_threats:
            print(f"Top {len(summary.top_threats)} Contributing Threats:")
            for i, threat in enumerate(summary.top_threats, 1):
                print(f"  {i}. {threat['threat_name']}")
                print(f"     Severity: {threat['severity']}, Confidence: {threat['confidence']:.3f}")
                print(f"     Priority Score: {threat['priority_score']}")
        print()
        print()


def demo_json_serialization():
    """Demonstrate JSON serialization for APIs."""
    print("=" * 80)
    print("JSON SERIALIZATION FOR APIs")
    print("=" * 80)
    print()
    
    metrics = example_metrics_warning()
    threats = map_metrics_to_threats(metrics, output_mode="detailed")
    summary = aggregate_dataset_threats(threats)
    
    # Convert to JSON
    json_output = summary.to_dict()
    
    print("Dataset Risk Summary (JSON):")
    print(json.dumps(json_output, indent=2))
    print()


def demo_integration_pattern():
    """Show how to integrate aggregation into existing workflows."""
    print("=" * 80)
    print("INTEGRATION PATTERN")
    print("=" * 80)
    print()
    
    print("Typical workflow:")
    print()
    print("1. Evaluate metrics (existing)")
    print("2. Map to threats (threat_mapping layer)")
    print("3. Aggregate to dataset risk (NEW aggregation layer)")
    print()
    
    # Simulate evaluation
    metrics = example_metrics_warning()
    
    # Map to threats
    threats = map_metrics_to_threats(metrics)
    print(f"✓ Detected {len(threats)} individual threat signals")
    
    # Aggregate to dataset level
    summary = aggregate_dataset_threats(threats)
    print(f"✓ Aggregated to dataset risk: {summary.overall_risk_level.upper()}")
    print()
    
    # Use risk level for advisory purposes
    print("Advisory Actions Based on Risk Level:")
    print()
    
    if summary.overall_risk_level == "critical":
        print("  ⚠️  CRITICAL RISK DETECTED")
        print("  → Recommend rejecting or heavily redacting dataset")
        print("  → Require manual security review")
        print(f"  → Focus on: {summary.top_threats[0]['threat_name']}")
        
    elif summary.overall_risk_level == "warning":
        print("  ⚡ WARNING - ELEVATED RISK")
        print("  → Recommend additional privacy controls")
        print("  → Consider differential privacy mechanisms")
        print(f"  → Address: {summary.top_threats[0]['threat_name']}")
        
    else:
        print("  ✓ LOW RISK")
        print("  → Standard governance practices apply")
        print("  → Monitor for drift in future evaluations")
    
    print()
    print("Note: These are ADVISORY recommendations, not automated decisions.")
    print()


def demo_escalation_transparency():
    """Show how escalation rules work for transparency."""
    print("=" * 80)
    print("ESCALATION RULES (TRANSPARENCY)")
    print("=" * 80)
    print()
    
    rules = explain_escalation_rules()
    
    for risk_level in ["critical", "warning", "low"]:
        print(f"{risk_level.upper()} Risk Triggers:")
        for i, reason in enumerate(rules[risk_level], 1):
            print(f"  {i}. {reason}")
        print()
    
    print("Rules are evaluated in order: CRITICAL → WARNING → LOW")
    print("First matching rule determines the risk level.")
    print()


if __name__ == "__main__":
    demo_aggregation_levels()
    print("\n\n")
    
    demo_json_serialization()
    print("\n\n")
    
    demo_integration_pattern()
    print("\n\n")
    
    demo_escalation_transparency()
    
    print("=" * 80)
    print("EXAMPLE COMPLETE")
    print("=" * 80)
    print("\nFor more details, see:")
    print("  - governance_core/threat_aggregation.py")
    print("  - governance_core/threat_mapping.py")
