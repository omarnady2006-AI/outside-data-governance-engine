"""
Example: Using Threat-Driven Metrics Mapping

This example demonstrates how to use the enhanced threat mapping layer with:
- Output modes (summary / detailed / json)
- Stable threat identifiers
- Confidence scores
- Triggered-by traceability

This is a standalone example showing the integration pattern.
"""

import sys
import os
# Add parent directory to path so we can import governance_core
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from governance_core.threat_mapping import (
    map_metrics_to_threats,
    get_threat_summary,
    list_all_threats,
    get_metrics_for_threat,
    # Import stable threat ID constants
    THREAT_MEMBERSHIP_INFERENCE,
    THREAT_PRIVACY_LEAKAGE,
    THREAT_DISTRIBUTION_DRIFT,
)


def example_metrics():
    """Return realistic evaluation metrics for demonstration."""
    return {
        # Top-level scores
        "privacy_score": 0.72,
        "utility_score": 0.88,
        "leakage_risk_level": "warning",
        "statistical_drift": "moderate",
        "semantic_violations": 3,
        "synthetic_rows": 5000,
        
        # Privacy risk metrics (nested)
        "privacy_risk": {
            "near_duplicates_count": 8,
            "near_duplicates_rate": 0.0016,
            "near_duplicates_threshold": 0.9,
            "membership_inference_auc": 0.627,
            "membership_inference_accuracy": 0.61,
            "min_nn_distance": 1.2,
            "avg_nn_distance": 3.4,
            "median_nn_distance": 3.1,
            "privacy_score": 0.72,
            "leakage_risk_level": "warning"
        },
        
        # Statistical fidelity metrics (nested)
        "statistical_fidelity": {
            "correlation_frobenius_norm": 1.23,
            "avg_histogram_overlap": 0.87,
            "avg_kl_divergence": 0.15,
            "avg_wasserstein_distance": 0.42,
            "drift_classification": "moderate"
        },
        
        # Utility metrics (nested)
        "utility_preservation": {
            "utility_score": 0.88,
            "utility_classification": "high",
            "synthetic_model_accuracy": 0.84,
            "real_model_accuracy": 0.87,
            "accuracy_gap": 0.03,
            "feature_importance_correlation": 0.91
        },
        
        # Semantic invariants (nested)
        "semantic_invariants": {
            "total_violations": 3,
            "field_constraint_violations": {"age": 2, "salary": 1},
            "cross_field_violations": []
        }
    }


def demo_output_modes():
    """Demonstrate the three output modes."""
    print("=" * 80)
    print("DEMONSTRATION: OUTPUT MODES")
    print("=" * 80)
    print()
    
    metrics = example_metrics()
    
    # Mode 1: Summary (counts only)
    print("[ Mode 1: SUMMARY - Counts Only ]")
    print("-" * 80)
    summary = map_metrics_to_threats(metrics, output_mode="summary")
    print(f"Total Threats: {summary['total_threats']}")
    print(f"By Severity: High={summary['severity_counts']['high']}, "
          f"Medium={summary['severity_counts']['medium']}, "
          f"Low={summary['severity_counts']['low']}")
    print(f"By Property: Privacy={summary['property_counts']['privacy']}, "
          f"Utility={summary['property_counts']['utility']}, "
          f"Consistency={summary['property_counts']['consistency']}")
    print()
    
    # Mode 2: Detailed (full ThreatSignal objects)
    print("[ Mode 2: DETAILED - Full Threat Objects ]")
    print("-" * 80)
    threats = map_metrics_to_threats(metrics, output_mode="detailed")
    print(f"Returned {len(threats)} ThreatSignal objects")
    print("\nExample threat object:")
    if threats:
        t = threats[0]  # Show first threat
        print(f"  ID: {t.threat_id}")
        print(f"  Name: {t.threat_name}")
        print(f"  Severity: {t.severity}")
        print(f"  Confidence: {t.confidence}")
        print(f"  Triggered by: {t.triggered_by}")
    print()
    
    # Mode 3: JSON (for APIs / audit logs)
    print("[ Mode 3: JSON - Serializable Dict ]")
    print("-" * 80)
    json_output = map_metrics_to_threats(metrics, output_mode="json")
    print(f"Keys: {list(json_output.keys())}")
    print(f"Contains {len(json_output['threats'])} threat dicts")
    print("\nFirst threat as JSON:")
    print(json.dumps(json_output['threats'][0], indent=2))
    print()


def demo_new_features():
    """Demonstrate new features: confidence, triggered_by, stable IDs."""
    print("=" * 80)
    print("DEMONSTRATION: NEW FEATURES")
    print("=" * 80)
    print()
    
    metrics = example_metrics()
    threats = map_metrics_to_threats(metrics, output_mode="detailed")
    
    print("[ Feature 1: Stable Threat IDs (Constants) ]")
    print("-" * 80)
    print("You can now use stable constants for threat IDs:")
    print(f"  THREAT_MEMBERSHIP_INFERENCE = '{THREAT_MEMBERSHIP_INFERENCE}'")
    print(f"  THREAT_PRIVACY_LEAKAGE = '{THREAT_PRIVACY_LEAKAGE}'")
    print(f"  THREAT_DISTRIBUTION_DRIFT = '{THREAT_DISTRIBUTION_DRIFT}'")
    print("\nDetected threat IDs in this evaluation:")
    for t in threats:
        print(f"  - {t.threat_id}")
    print()
    
    print("[ Feature 2: Confidence Scores ]")
    print("-" * 80)
    print("Each threat now includes a confidence score (0.0-1.0):")
    print()

    
    for threat in threats:
        print(f"{threat.threat_name}:")
        print(f"  Severity: {threat.severity}")
        print(f"  Confidence: {threat.confidence:.3f}")
        print(f"  Related Metrics:")
        for metric_name, value in threat.metric_values.items():
            if isinstance(value, (int, float)):
                print(f"    - {metric_name}: {value}")
        print(f"  Triggered By:")
        for condition in threat.triggered_by:
            print(f"    → {condition}")
        print(f"  Risk: {threat.impacted_property.upper()}")
        print()


def demo_integration_patterns():
    """Show integration patterns for different use cases."""
    print("=" * 80)
    print("INTEGRATION PATTERNS")
    print("=" * 80)
    print()
    
    metrics = example_metrics()
    
    print("[ Pattern 1: CLI Dashboard ]")
    print("-" * 80)
    print("Use 'summary' mode for quick CLI output:")
    print()
    summary = map_metrics_to_threats(metrics, output_mode="summary")
    print("Threat Assessment:")
    print(f"  ⚠️  High severity:   {summary['severity_counts']['high']}")
    print(f"  ⚡ Medium severity: {summary['severity_counts']['medium']}")
    print(f"  ℹ️  Low severity:    {summary['severity_counts']['low']}")
    print()
    print(f"Impact Areas:")
    print(f"  🔒 Privacy:     {summary['property_counts']['privacy']} threats")
    print(f"  📊 Utility:     {summary['property_counts']['utility']} threats")
    print(f"  ✔️  Consistency: {summary['property_counts']['consistency']} threats")
    print()
    
    print("[ Pattern 2: Audit Logging ]")
    print("-" * 80)
    print("Use 'json' mode for audit trails:")
    print()
    json_data = map_metrics_to_threats(metrics, output_mode="json")
    audit_record = {
        "evaluation_id": "eval_20260202_001",
        "timestamp": "2026-02-02T18:08:00Z",
        "privacy_score": metrics["privacy_score"],
        "threat_analysis": json_data
    }
    print("Audit record structure:")
    print(json.dumps(audit_record, indent=2)[:500] + "...")
    print()
    
    print("[ Pattern 3: Conditional Alerts ]")
    print("-" * 80)
    print("Use stable IDs for targeted responses:")
    print()
    threats = map_metrics_to_threats(metrics, output_mode="detailed")
    
    # Check for specific threats
    threat_ids = [t.threat_id for t in threats]
    
    if THREAT_MEMBERSHIP_INFERENCE in threat_ids:
        mi_threat = next(t for t in threats if t.threat_id == THREAT_MEMBERSHIP_INFERENCE)
        print(f"⚠️  ALERT: {mi_threat.threat_name} detected!")
        print(f"   Severity: {mi_threat.severity.upper()}")
        print(f"   Confidence: {mi_threat.confidence:.1%}")
        print(f"   Action: Consider differential privacy mechanisms")
    
    if THREAT_PRIVACY_LEAKAGE in threat_ids:
        pl_threat = next(t for t in threats if t.threat_id == THREAT_PRIVACY_LEAKAGE)
        print(f"⚠️  ALERT: {pl_threat.threat_name} detected!")
        print(f"   Severity: {pl_threat.severity.upper()}")
        print(f"   Confidence: {pl_threat.confidence:.1%}")
        print(f"   Action: Review privacy score thresholds")
    print()


def demo_backward_compatibility():
    """Verify backward compatibility with original API."""
    print("=" * 80)
    print("BACKWARD COMPATIBILITY CHECK")
    print("=" * 80)
    print()
    
    metrics = example_metrics()
    
    # Original usage (default mode = "detailed")
    threats = map_metrics_to_threats(metrics)  # No output_mode specified
    
    print("✓ Original API works (no output_mode parameter)")
    print(f"  Returns: List[ThreatSignal] with {len(threats)} items")
    print()
    
    # Can still use get_threat_summary
    summary = get_threat_summary(threats)
    print("✓ get_threat_summary() still works")
    print(f"  Returns: Dict with {len(summary)} keys")
    print()
    
    # Utility functions still work
    all_threats = list_all_threats()
    print("✓ Utility functions still work")
    print(f"  list_all_threats() returns {len(all_threats)} threat IDs")
    print()
    
    print("✅ All backward compatibility checks passed!")
    print()


if __name__ == "__main__":
    # Run all demonstrations
    demo_output_modes()
    print("\n\n")
    
    demo_new_features()
    print("\n\n")
    
    demo_integration_patterns()
    print("\n\n")
    
    demo_backward_compatibility()
    
    print("=" * 80)
    print("EXAMPLE COMPLETE")
    print("=" * 80)
    print("\nFor more details, see: governance_core/threat_mapping.py")



def example_threat_mapping():
    """
    Demonstrate threat mapping with a realistic evaluation result.
    """
    
    # Example evaluation metrics from a typical governance evaluation
    # (This would normally come from RuleEngine.evaluate_synthetic_data())
    example_metrics = {
        # Top-level scores
        "privacy_score": 0.72,
        "utility_score": 0.88,
        "leakage_risk_level": "warning",
        "statistical_drift": "moderate",
        "semantic_violations": 3,
        "synthetic_rows": 5000,
        
        # Privacy risk metrics (nested)
        "privacy_risk": {
            "near_duplicates_count": 8,
            "near_duplicates_rate": 0.0016,
            "near_duplicates_threshold": 0.9,
            "membership_inference_auc": 0.627,
            "membership_inference_accuracy": 0.61,
            "min_nn_distance": 1.2,
            "avg_nn_distance": 3.4,
            "median_nn_distance": 3.1,
            "privacy_score": 0.72,
            "leakage_risk_level": "warning"
        },
        
        # Statistical fidelity metrics (nested)
        "statistical_fidelity": {
            "correlation_frobenius_norm": 1.23,
            "avg_histogram_overlap": 0.87,
            "avg_kl_divergence": 0.15,
            "avg_wasserstein_distance": 0.42,
            "drift_classification": "moderate"
        },
        
        # Utility metrics (nested)
        "utility_preservation": {
            "utility_score": 0.88,
            "utility_classification": "high",
            "synthetic_model_accuracy": 0.84,
            "real_model_accuracy": 0.87,
            "accuracy_gap": 0.03,
            "feature_importance_correlation": 0.91
        },
        
        # Semantic invariants (nested)
        "semantic_invariants": {
            "total_violations": 3,
            "field_constraint_violations": {"age": 2, "salary": 1},
            "cross_field_violations": []
        }
    }
    
    print("=" * 80)
    print("THREAT-DRIVEN METRICS MAPPING EXAMPLE")
    print("=" * 80)
    print()
    
    # Step 1: Map metrics to threats
    print("Step 1: Mapping metrics to threat signals...")
    print("-" * 80)
    
    threat_signals = map_metrics_to_threats(example_metrics)
    
    print(f"Detected {len(threat_signals)} threat signals")
    print()
    
    # Step 2: Display each threat signal
    print("Step 2: Detailed threat signals")
    print("-" * 80)
    
    for i, signal in enumerate(threat_signals, 1):
        print(f"\n[{i}] {signal.threat_name}")
        print(f"    Threat ID: {signal.threat_id}")
        print(f"    Attack Type: {signal.attack_type}")
        print(f"    Impacted Property: {signal.impacted_property.upper()}")
        print(f"    Severity: {signal.severity.upper()}")
        print(f"    Related Metrics: {', '.join(signal.related_metrics)}")
        print(f"    Metric Values:")
        for metric_name, value in signal.metric_values.items():
            if isinstance(value, float):
                print(f"      - {metric_name}: {value:.4f}")
            else:
                print(f"      - {metric_name}: {value}")
        print(f"    Description: {signal.description}")
    
    print()
    
    # Step 3: Get threat summary
    print("Step 3: Threat summary")
    print("-" * 80)
    
    summary = get_threat_summary(threat_signals)
    
    print(f"Total Threats: {summary['total_threats']}")
    print()
    print("By Severity:")
    print(f"  - High:   {summary['severity_counts']['high']} threats")
    print(f"  - Medium: {summary['severity_counts']['medium']} threats")
    print(f"  - Low:    {summary['severity_counts']['low']} threats")
    print()
    print("By Impacted Property:")
    print(f"  - Privacy:     {summary['property_counts']['privacy']} threats")
    print(f"  - Utility:     {summary['property_counts']['utility']} threats")
    print(f"  - Consistency: {summary['property_counts']['consistency']} threats")
    print()
    
    # Step 4: Show available threat catalog
    print("Step 4: Available threat definitions")
    print("-" * 80)
    
    all_threats = list_all_threats()
    print(f"Threat catalog contains {len(all_threats)} threat types:")
    for threat_id in all_threats:
        metrics = get_metrics_for_threat(threat_id)
        print(f"  - {threat_id}: monitors {len(metrics)} metrics")
    
    print()
    
    # Step 5: Export as JSON for governance records
    print("Step 5: JSON export for audit/governance")
    print("-" * 80)
    
    # Convert to serializable format
    threat_export = {
        "evaluation_summary": {
            "privacy_score": example_metrics["privacy_score"],
            "utility_score": example_metrics["utility_score"],
            "semantic_violations": example_metrics["semantic_violations"]
        },
        "threat_signals": [
            {
                "threat_id": s.threat_id,
                "threat_name": s.threat_name,
                "attack_type": s.attack_type,
                "impacted_property": s.impacted_property,
                "severity": s.severity,
                "related_metrics": s.related_metrics,
                "metric_values": s.metric_values,
                "description": s.description
            }
            for s in threat_signals
        ],
        "summary": summary
    }
    
    json_output = json.dumps(threat_export, indent=2)
    print(json_output)
    
    print()
    print("=" * 80)
    print("EXAMPLE COMPLETE")
    print("=" * 80)
    
    return threat_signals, summary


def integration_example():
    """
    Show how to integrate threat mapping into existing governance workflow.
    """
    print("\n\n")
    print("=" * 80)
    print("INTEGRATION PATTERN")
    print("=" * 80)
    print("""
The threat mapping layer can be integrated into your existing workflow:

1. In RuleEngine or GovernanceAgent:
   
   from governance_core.threat_mapping import map_metrics_to_threats, get_threat_summary
   
   def evaluate_with_threats(self, synthetic_df, original_df):
       # Existing evaluation
       metrics = self.evaluate_synthetic_data(synthetic_df, original_df)
       
       # Add threat interpretation (OPTIONAL, non-blocking)
       try:
           threat_signals = map_metrics_to_threats(metrics)
           threat_summary = get_threat_summary(threat_signals)
           
           # Optionally add to metrics output
           metrics['threat_analysis'] = {
               'signals': threat_signals,
               'summary': threat_summary
           }
       except Exception as e:
           logger.warning(f"Threat mapping failed (non-critical): {e}")
       
       return metrics

2. In reporting/audit logging:
   
   from governance_core.threat_mapping import map_metrics_to_threats
   
   def generate_audit_report(eval_id, metrics):
       # Map threats for governance interpretation
       threats = map_metrics_to_threats(metrics)
       
       # Include threat-based interpretation in audit log
       audit_logger.log_evaluation(
           eval_id=eval_id,
           metrics=metrics,
           threat_signals=[t.__dict__ for t in threats]
       )

3. In CLI output:
   
   threats = map_metrics_to_threats(result['metrics'])
   summary = get_threat_summary(threats)
   
   print(f"\\nThreat Assessment:")
   print(f"  High severity threats: {summary['severity_counts']['high']}")
   print(f"  Privacy threats:       {summary['property_counts']['privacy']}")

IMPORTANT:
- Threat mapping is purely advisory/interpretive
- It does NOT affect APPROVE/REJECT decisions
- It does NOT change metric computation
- Integration is optional and failure-tolerant
- Backward-compatible with all existing code
    """)
    print("=" * 80)


if __name__ == "__main__":
    # Run the example
    threat_signals, summary = example_threat_mapping()
    
    # Show integration pattern
    integration_example()
    
    print("\nFor more details, see: governance_core/threat_mapping.py")
