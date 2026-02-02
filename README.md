# Outside Data Governance Engine

**A governance interpretation layer for synthetic data risk assessment.**

This engine interprets evaluation metrics from synthetic datasets and produces structured privacy, utility, and consistency threat assessments. It is advisory-only. It does not make approval, rejection, or deployment decisions.

---

## Project Overview

### What This Is

A post-evaluation analysis component that maps raw statistical metrics (privacy scores, utility scores, distributional measures) to explicit threat signals (membership inference, record linkage, distribution drift, etc.).

**Problem Solved**: Synthetic data evaluation outputs numerous disconnected metrics. Security teams and data stewards cannot efficiently assess whether a dataset poses privacy risks, maintains analytical value, or respects domain constraints without structured interpretation. This engine provides that interpretation layer.

**Architectural Layer**: Sits between metric computation and decision-making. Consumes evaluation results. Produces risk interpretations. Does not choose actions.

### Why It Exists

Organizations generating synthetic data need a systematic way to understand evaluation results without building custom threat analysis logic for each deployment. This engine standardizes threat signal mapping, risk aggregation, and uncertainty handling as a reusable, auditable component.

---

## Core Design Principles

### 1. Advisory-Only Governance

This engine **interprets** governance risks. It does **not** make decisions.

- Outputs describe risk levels, threat signals, and confidence scores
- No "APPROVED" or "REJECTED" status is ever returned
- No deployment gates, pipeline controls, or blocking logic exists in this system
- Results inform human review or downstream policy engines—they do not replace them

### 2. Separation of Interpretation vs Enforcement

**Interpretation**: Mapping metrics to threats with severity and confidence.  
**Enforcement**: Deciding what to do about those threats (approve, reject, regenerate, audit).

This engine handles interpretation only. Enforcement belongs in orchestration layers, policy engines, or human decision-makers that consume this engine's output.

**Rationale**: Separating these concerns ensures reusability across different risk tolerance policies, testability of threat detection independent of action logic, and auditability of "what was detected" vs "what was decided."

### 3. Zero-Trust Toward Automation

No component of this system is designed to operate autonomously without oversight.

- All outputs include uncertainty flags and disclaimers
- Missing or invalid metrics trigger explicit degradation, not silent defaults
- LLM-generated content (if enabled) is treated as untrusted advisory text, never parsed for decisions
- Audit logging is mandatory for all evaluations

**Design Goal**: Make silent approval/rejection architecturally impossible.

### 4. Non-Gateable Outputs by Design

Results from this engine cannot be trivially misused as automated gates.

- No boolean "is_safe" or "should_deploy" fields exist
- Risk levels are interpretive categories ("low", "warning", "critical"), not binary pass/fail
- Every result includes disclaimers stating it is advisory-only
- Uncertainty indicators force downstream systems to handle data quality explicitly

**Intentional Friction**: Systems attempting to automate decisions based on this output must write explicit, auditable logic that cannot be hidden behind a single function call.

---

## What This Engine DOES

- **Threat Signal Mapping**: Interprets metrics into categorized threats with severity (low/medium/high) and confidence scores (0.0–1.0)
- **Risk Aggregation**: Combines individual threats into dataset-level risk summaries (low/warning/critical)
- **Structured Output**: Provides JSON-serializable results with metadata, timestamps, and uncertainty indicators
- **Safe Degradation**: Handles missing or invalid metrics gracefully without crashing or producing misleading results
- **Auditability**: Tracks triggered conditions, metric values, and escalation logic for transparency
- **Public API Facade**: Exposes a stable, simple interface (`evaluate_governance`) for external integration
- **Uncertainty Propagation**: Flags data quality issues explicitly in every result

---

## What This Engine DOES NOT DO

This section is **critical** to prevent misuse.

### Does NOT Make Pipeline Decisions

This engine **does not** approve, reject, accept, deny, allow, block, or gate dataset deployments.

**What it does instead**: Returns risk assessments with severity levels and confidence scores that inform decision-making systems.

**Example of correct usage**:

```python
result = evaluate_governance(metrics)
if result.dataset_risk_summary.overall_risk_level == "critical":
    # Human review required - send to security team
    notify_security_team(result)
```

**Example of incorrect usage** (conceptually):

```python
# WRONG - treating advisory output as automated decision
result = evaluate_governance(metrics)
if result.dataset_risk_summary.overall_risk_level == "low":
    deploy_to_production()  # Silent automation - violates design intent
```

### Does NOT Modify or Fix Data

This engine is read-only with respect to datasets. It analyzes metrics and reports findings. It does not regenerate, transform, sanitize, or "repair" datasets.

**Rationale**: Automated data "fixes" can introduce subtle biases, mask underlying generation failures, or violate domain constraints in ways that are difficult to audit.

### Does NOT Compute Metrics

This engine assumes all statistical evaluation (KL divergence, membership inference attacks, nearest-neighbor analysis) has already been performed. It operates on pre-computed metric dictionaries.

**What it expects**: Input like `{"privacy_score": 0.85, "utility_score": 0.90, ...}`

**What it does not do**: Run statistical tests, train ML models, or execute computations beyond threat mapping logic.

### Does NOT Certify Compliance

This engine does not enforce GDPR, HIPAA, CCPA, or other regulatory compliance rules. It provides technical risk assessments that may inform compliance workflows, but compliance determination requires legal review and contextual factors beyond metric analysis.

### Does NOT Provide Mathematical Privacy Guarantees

This engine detects empirical privacy risks (near-duplicates, membership inference success rates) but does not prove or guarantee differential privacy, k-anonymity, or other formal privacy definitions.

**Clarification**: If formal privacy guarantees are required, they must come from the synthetic data generation process itself (e.g., DP-SGD, DP-GAN), not post-hoc analysis.

### Does NOT Operate Autonomously

This engine does not run as a standalone service, make unsolicited external API calls, or operate without human oversight. It is designed as a library component to be integrated into larger systems.

**Intentional Constraint**: Autonomy increases attack surface and reduces transparency. Human-in-the-loop review is by design.

### Does NOT Provide Real-Time Processing

Threat aggregation is a batch-oriented process suitable for post-generation validation, not real-time inference.

**Rationale**: Governance is a deliberate, accuracy-focused activity, not a latency-optimized one.

---

## High-Level Architecture

### Processing Flow

```
1. Metrics Computed
   External evaluation layer produces privacy, utility, and consistency scores

2. Threat Mapping
   Metrics → specific threat signals with confidence and severity
   (membership inference, record linkage, distribution drift, etc.)

3. Risk Aggregation
   Threat signals → dataset-level risk summary with escalation logic
   (low/warning/critical determination)

4. Output Construction
   Structured result (GovernanceResult) with threats, risk level, uncertainty flags

5. Consumer Integration
   Dashboard, policy engine, or audit system uses result for advisory purposes
   NO automated decision-making occurs within this engine
```

### Component Layers

- **Public API** (`governance_core/api.py`): Single entry-point function `evaluate_governance()`
- **Threat Mapping** (`governance_core/threat_mapping.py`): Metric-to-threat conversion logic
- **Threat Aggregation** (`governance_core/threat_aggregation.py`): Dataset-level risk summarization
- **Audit Logging** (optional): Records all evaluations for transparency

### Architectural Constraints

- **Functional Core**: No hidden state, no side effects beyond logging
- **Dataclass Outputs**: Structured, type-safe results
- **No External Dependencies**: Core engine uses Python stdlib only
- **Version Tracking**: All results include engine version and timestamp

---

## Public API (Minimal)

Single entry-point function for integration:

```python
from governance_core import evaluate_governance

# Basic usage
result = evaluate_governance(
    metrics={
        "privacy_score": 0.85,
        "utility_score": 0.90,
        "privacy_risk": {"membership_inference_auc": 0.52}
    },
    output_mode="summary"  # or "detailed" or "full"
)

# Interpret results (advisory only)
print(result.dataset_risk_summary.overall_risk_level)  # "low" | "warning" | "critical"
print(result.has_uncertainty)  # Boolean flag for data quality issues
print(result.disclaimers)  # Advisory-only notices

# Access detailed threats (if output_mode="detailed")
for threat in result.threats:
    print(f"{threat.threat_name}: {threat.severity} (confidence: {threat.confidence})")
```

### What the API Returns

`GovernanceResult` contains:

- `dataset_risk_summary`: Aggregated risk assessment (DatasetRiskSummary)
- `threats`: Individual threat signals (optional, based on output_mode)
- `has_uncertainty`: Data quality flag (boolean)
- `uncertainty_notes`: Human-readable explanations of issues (list of strings)
- `metadata`: Version, timestamp, configuration (dict)
- `disclaimers`: Advisory-only notices (list of strings)

### What the API Does NOT Return

- No "approved" or "rejected" boolean
- No "should_deploy" or "is_safe" flag
- No numeric "pass score" or threshold comparison result
- No actionable commands ("regenerate", "block", "allow")

**Emphasis**: Results are interpretive risk context, not decision outputs.

---

## Safety & Misuse Prevention

### Why Outputs Cannot Be Used as Automated Gates

1. **No Binary Decisions**: Risk levels are categories ("low", "warning", "critical"), not boolean pass/fail values requiring explicit interpretation logic downstream.

2. **Mandatory Disclaimers**: Every result includes disclaimers stating this is advisory-only, forcing consumers to acknowledge the interpretive nature.

3. **Uncertainty Flags**: Missing or invalid metrics trigger explicit flags, not silent defaults that might enable unintended automation.

4. **No Actionable Fields**: No "recommended_action" or "next_steps" fields exist that could be blindly executed.

### How the Design Prevents Silent Approval/Rejection

**Architectural Safeguards**:

- Risk levels require string comparison, not simple boolean checks
- No result structure maps to "proceed" vs "halt" without custom logic
- Disclaimers cannot be suppressed or removed from results
- Uncertainty propagation forces explicit handling of edge cases

**Code Review Pattern**: Systems integrating this engine must write explicit decision logic (e.g., "if critical, notify team; if warning, require review; if low, document and proceed"). This logic is visible, auditable, and cannot be hidden behind a single function call.

### Role of Uncertainty and Disclaimers

**Uncertainty Handling**: When metrics are missing, invalid, or insufficient, the engine returns a valid result with `has_uncertainty=True` and descriptive notes. This prevents downstream systems from making decisions based on incomplete information without explicit acknowledgment.

**Disclaimers**: Every result includes standardized text:

- "This assessment is advisory only and does not constitute compliance certification"
- "Risk levels are interpretive and should inform, not replace, human decision-making"
- "No approval or rejection decisions are made by this system"

**Intent**: Make it difficult to present engine output as authoritative decision validation.

---

## When NOT to Use This Project

Do not use this engine if you need:

### Enforcement or Policy Execution

If you need a system that **blocks** unsafe datasets from deployment, **enforces** compliance rules, or **gates** CI/CD pipelines, this is not the right tool. You need a policy enforcement engine that uses this engine's output as one input among many.

### Automated Approval Workflows

If you want a system that **automatically approves** low-risk datasets without human oversight, this engine is not designed for that use case. Its outputs are advisory and require interpretation.

### Compliance Certification

If you need a system that **certifies** GDPR, HIPAA, or CCPA compliance, this engine cannot provide that. It offers technical risk assessments that may inform compliance workflows, but legal certification requires regulatory expertise beyond metric analysis.

### Real-Time Decision-Making

If you need sub-second evaluation for streaming data or production inference gating, this engine's batch-oriented design is not suitable.

### Data Generation or Repair

If you need to **generate synthetic data** or **automatically fix** privacy leakage issues, this engine does not provide those capabilities. It only interprets evaluation results.

### Standalone Security System

If you need a complete data governance platform with dashboards, alerting, workflow management, and access control, this engine is a component, not a complete solution.

---

## Related Documentation

### Core Documentation

- **[Scope and Boundaries](docs/SCOPE_AND_BOUNDARIES.md)**: Detailed definition of what this engine does and does not do
- **[Threat Model](docs/THREAT_MODEL.md)**: Threat catalog, severity rules, and detection logic
- **[Leakage Metrics](docs/LEAKAGE_METRICS.md)**: Privacy risk metrics and interpretation

### Examples

- **[examples/public_api_example.py](examples/public_api_example.py)**: Public API usage patterns
- **[examples/threat_mapping_example.py](examples/threat_mapping_example.py)**: Threat signal mapping demonstrations
- **[examples/threat_aggregation_example.py](examples/threat_aggregation_example.py)**: Risk aggregation workflows

### Testing

- **[TEST_GUIDE.md](TEST_GUIDE.md)**: Testing strategy and execution
- **[LLM_TESTING_GUIDE.md](LLM_TESTING_GUIDE.md)**: Optional LLM advisory layer testing

---

## Installation

```bash
pip install -e .
```

**Requirements**: Python 3.7+ (uses stdlib dataclasses)

**Dependencies**: None for core engine (stdlib only)

---

## License

MIT License. See LICENSE for details.

---

## Technical Details

**Version**: 2.1.0  
**Language**: Python  
**Architecture**: Functional core with dataclass outputs  
**Testing**: Unit tests and examples in `examples/test_*.py`  
**API Stability**: Public API (`evaluate_governance`) follows semantic versioning  

---

## Advisory-Only Notice

**This engine provides risk interpretation, not deployment authorization.**

All results are informational. They describe governance risks but do not decide what actions to take. Decision-making must involve human review, policy engine logic configured by your organization, or other explicit governance processes that you control.

**No approval or rejection decisions are made by this system.**
