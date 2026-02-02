# Outside Data Governance Engine

**A governance interpretation layer for synthetic data risk assessment.**

This engine analyzes synthetic dataset evaluation metrics and produces structured privacy, utility, and consistency threat assessments. It is advisory-only and does not make deployment decisions.

---

## What This Is

A post-evaluation analysis component that maps raw statistical metrics (privacy scores, utility scores, distributional measures) to explicit threat signals (membership inference, record linkage, distribution drift, etc.).

**Architectural Layer**: Sits between metric computation and decision-making. Consumes evaluation results, produces risk interpretations.

**Design Philosophy**: Advisory, read-only, transparent. Answers "what risks are present" but not "what to do about them."

---

## What It Does

- **Threat Signal Mapping**: Interprets metrics into categorized threats with severity (low/medium/high) and confidence scores (0.0–1.0)
- **Risk Aggregation**: Combines individual threats into dataset-level risk summaries (low/warning/critical)
- **Structured Output**: Provides JSON-serializable results with metadata, timestamps, and uncertainty indicators
- **Safe Degradation**: Handles missing or invalid metrics gracefully without crashing
- **Auditability**: Tracks triggered conditions, metric values, and escalation logic for transparency

---

## What It Does NOT Do

- **Pipeline Decisions**: Does not approve, reject, or gate dataset deployments
- **Data Modification**: Does not regenerate, fix, or transform datasets
- **Metric Computation**: Does not run statistical tests or train models; operates on pre-computed metrics
- **Compliance Enforcement**: Does not implement GDPR, HIPAA, or other regulatory rules
- **Privacy Guarantees**: Does not prove differential privacy or k-anonymity mathematically
- **Real-Time Processing**: Batch-oriented analysis, not sub-second evaluation

---

## Core Flow

```
1. Metrics computed by external evaluation layer (privacy, utility, consistency scores)
2. Threat mapping: metrics → specific threat signals with confidence and severity
3. Aggregation: threat signals → dataset-level risk summary with escalation logic
4. Output: structured result (GovernanceResult) with threats, risk level, uncertainty flags
5. Consumer (dashboard, policy engine, audit system) uses result for advisory purposes
```

---

## Public API

Single entry-point function for integration:

```python
from governance_core import evaluate_governance

result = evaluate_governance(
    metrics={"privacy_score": 0.85, "utility_score": 0.90, ...},
    output_mode="summary"  # or "detailed" or "full"
)

print(result.dataset_risk_summary.overall_risk_level)  # "low" | "warning" | "critical"
```

Returns `GovernanceResult` with:
- `dataset_risk_summary`: Aggregated risk assessment
- `threats`: Individual threat signals (optional, based on output_mode)
- `has_uncertainty`: Data quality flag
- `metadata`: Version, timestamp, configuration

---

## Installation

```bash
pip install -e .
```

Requires Python 3.7+ (uses stdlib dataclasses, no external dependencies for core engine).

---

## Where to Learn More

### Core Documentation
- **[Scope and Boundaries](docs/SCOPE_AND_BOUNDARIES.md)**: Detailed definition of what this engine does and does not do
- **[Threat Model](docs/THREAT_MODEL.md)**: Threat catalog, severity rules, and detection logic
- **[Leakage Metrics](docs/LEAKAGE_METRICS.md)**: Privacy risk metrics and interpretation

### Governance Details
- **[README_GOVERNANCE.md](README_GOVERNANCE.md)**: Zero-trust LLM governance architecture (optional layer)

### Examples
- **[examples/public_api_example.py](examples/public_api_example.py)**: Public API usage patterns
- **[examples/threat_mapping_example.py](examples/threat_mapping_example.py)**: Threat signal mapping demonstrations
- **[examples/threat_aggregation_example.py](examples/threat_aggregation_example.py)**: Risk aggregation workflows

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Technical Notes

**Version**: 2.1.0  
**Language**: Python  
**Architecture**: Functional core with dataclass outputs  
**Testing**: See `run_unit_tests.py` and `examples/test_*.py`  
**Dependencies**: None (core engine uses stdlib only)

**Advisory-Only Notice**: This engine provides risk interpretation, not deployment authorization. All results should inform human review or policy engine logic, not replace it.
