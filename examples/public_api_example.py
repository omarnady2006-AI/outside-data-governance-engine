"""
Lightweight Example: Public API Usage

Demonstrates the new public API facade for the Outside Data Governance Engine.
Shows safe usage patterns including partial input and error handling.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from governance_core import evaluate_governance


def example_normal_usage():
    """Example 1: Normal usage with typical metrics."""
    print("=" * 80)
    print("EXAMPLE 1: Normal Usage")
    print("=" * 80)
    print()
    
    metrics = {
        "privacy_score": 0.85,
        "utility_score": 0.90,
        "privacy_risk": {
            "membership_inference_auc": 0.52,
            "near_duplicates_count": 3
        },
        "statistical_fidelity": {
            "avg_kl_divergence": 0.12
        }
    }
    
    result = evaluate_governance(metrics)
    
    print(f"Overall Risk Level: {result.dataset_risk_summary.overall_risk_level}")
    print(f"Total Threats: {result.dataset_risk_summary.total_threats}")
    print(f"Has Uncertainty: {result.has_uncertainty}")
    print()
    print(f"Summary: {result.dataset_risk_summary.summary_text}")
    print()


def example_detailed_mode():
    """Example 2: Get detailed threat information."""
    print("=" * 80)
    print("EXAMPLE 2: Detailed Mode (Includes Threats)")
    print("=" * 80)
    print()
    
    metrics = {
        "privacy_score": 0.72,
        "utility_score": 0.88,
        "privacy_risk": {
            "membership_inference_auc": 0.65,
            "near_duplicates_rate": 0.015
        }
    }
    
    result = evaluate_governance(metrics, output_mode="detailed")
    
    print(f"Overall Risk Level: {result.dataset_risk_summary.overall_risk_level.upper()}")
    print(f"Total Threats Detected: {result.dataset_risk_summary.total_threats}")
    print()
    
    if result.threats:
        print("Individual Threats:")
        for i, threat in enumerate(result.threats, 1):
            print(f"  {i}. {threat.threat_name}")
            print(f"     Severity: {threat.severity}, Confidence: {threat.confidence:.3f}")
            print(f"     Property: {threat.impacted_property}")
    print()


def example_partial_input():
    """Example 3: Partial/minimal metrics (graceful degradation)."""
    print("=" * 80)
    print("EXAMPLE 3: Partial Input (Safe Degradation)")
    print("=" * 80)
    print()
    
    # Only minimal metrics provided
    metrics = {
        "privacy_score": 0.80
    }
    
    result = evaluate_governance(metrics)
    
    print(f"Overall Risk Level: {result.dataset_risk_summary.overall_risk_level}")
    print(f"Total Threats: {result.dataset_risk_summary.total_threats}")
    print(f"Has Uncertainty: {result.has_uncertainty}")
    
    if result.uncertainty_notes:
        print()
        print("Uncertainty Notes:")
        for note in result.uncertainty_notes:
            print(f"  - {note}")
    print()


def example_empty_input():
    """Example 4: Empty input (error handling)."""
    print("=" * 80)
    print("EXAMPLE 4: Empty Input (Error Handling)")
    print("=" * 80)
    print()
    
    # Empty metrics
    result = evaluate_governance({})
    
    print(f"Overall Risk Level: {result.dataset_risk_summary.overall_risk_level}")
    print(f"Has Uncertainty: {result.has_uncertainty}")
    print(f"Summary: {result.dataset_risk_summary.summary_text}")
    
    if result.uncertainty_notes:
        print()
        print("Uncertainty Notes:")
        for note in result.uncertainty_notes:
            print(f"  - {note}")
    print()


def example_json_export():
    """Example 5: JSON serialization for APIs."""
    print("=" * 80)
    print("EXAMPLE 5: JSON Export")
    print("=" * 80)
    print()
    
    import json
    
    metrics = {
        "privacy_score": 0.88,
        "utility_score": 0.92
    }
    
    result = evaluate_governance(metrics, output_mode="summary")
    
    # Convert to JSON
    result_dict = result.to_dict()
    
    print("JSON Output (truncated):")
    print(json.dumps(result_dict, indent=2)[:500] + "...")
    print()
    print(f"Metadata Keys: {list(result_dict['metadata'].keys())}")
    print(f"Engine Version: {result_dict['metadata']['engine_version']}")
    print()


def example_philosophy_check():
    """Example 6: Verify advisory-only behavior."""
    print("=" * 80)
    print("EXAMPLE 6: Advisory-Only Philosophy Check")
    print("=" * 80)
    print()
    
    metrics = {
        "privacy_score": 0.55,  # Low privacy
        "utility_score": 0.60,  # Low utility
        "privacy_risk": {
            "membership_inference_auc": 0.78  # High attack risk
        }
    }
    
    result = evaluate_governance(metrics, output_mode="detailed")
    
    print("High-risk dataset evaluation:")
    print(f"  Risk Level: {result.dataset_risk_summary.overall_risk_level.upper()}")
    print(f"  Total Threats: {result.dataset_risk_summary.total_threats}")
    print()
    
    # Check that result contains NO decision fields
    result_dict = result.to_dict()
    
    print("Checking for decision/approval fields...")
    forbidden_keys = ['decision', 'approve', 'reject', 'approved', 'rejected', 'accept']
    found_forbidden = []
    
    def check_dict_recursive(d, path=""):
        for key, value in d.items():
            if any(forbidden in key.lower() for forbidden in forbidden_keys):
                found_forbidden.append(f"{path}.{key}" if path else key)
            if isinstance(value, dict):
                check_dict_recursive(value, f"{path}.{key}" if path else key)
    
    check_dict_recursive(result_dict)
    
    if found_forbidden:
        print(f"  ❌ FAILED: Found decision fields: {found_forbidden}")
    else:
        print("  ✅ PASSED: No decision/approval fields found")
        print("  ✅ Engine is advisory-only as required")
    print()
    
    print("This result should be used for:")
    print("  - Risk assessment and reporting")
    print("  - Human review and decision support")
    print("  - Audit trails and governance documentation")
    print()
    print("This result should NOT be used to:")
    print("  - Automatically approve/reject datasets")
    print("  - Gate production deployments without human review")
    print("  - Make binding compliance decisions")
    print()


if __name__ == "__main__":
    print()
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 20 + "PUBLIC API FACADE EXAMPLES" + " " * 32 + "║")
    print("╚" + "=" * 78 + "╝")
    print()
    
    # Run all examples
    example_normal_usage()
    example_detailed_mode()
    example_partial_input()
    example_empty_input()
    example_json_export()
    example_philosophy_check()
    
    print("=" * 80)
    print("ALL EXAMPLES COMPLETE")
    print("=" * 80)
    print()
    print("Usage Pattern:")
    print("  from governance_core import evaluate_governance")
    print("  result = evaluate_governance(metrics)")
    print("  print(result.dataset_risk_summary.overall_risk_level)")
    print()
