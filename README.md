# Hybrid Data Governance Agent

**A zero-trust, production-grade system for evaluating synthetic data privacy, utility, and consistency.**

This project implements a **Hybrid Data Governance Agent** that combines deterministic statistical validation with optional LLM-powered interpretation. It provides robust quality gates for synthetic data pipelines while maintaining strict privacy standards.

## 🚀 High-Level Description

The Hybrid Data Governance Agent evaluates synthetic datasets to ensure they are safe, useful, and statistically representative before they are used in downstream applications. It solves the challenge of "black box" governance by separating metric calculation from interpretation.

**Core Philosophy:**
- **Deterministic Metrics**: Privacy, utility, and drift are calculated using standard, reproducible statistical tests.
- **Optional LLM Reasoning**: An LLM can be used to *explain* findings and *recommend* fix strategies, but it **never** executes decisions autonomously.
- **Zero-Trust Architecture**: The system assumes the LLM is untrusted. No raw data is ever shared with the LLM.

## 🏗️ Architecture Overview

The system consists of three strictly separated components:

### 1. Rule Engine (Deterministic)
The core validation layer. It executes code-based checks to produce input-invariant metrics.
- **Privacy Metrics**: Computes **k-anonymity–style risk indicators**, near-duplicate rates, and membership inference risk.
- **Utility Metrics**: Measures feature correlations, distribution fidelity (KL divergence), and downstream ML performance.
- **Outputs**: Purely numerical scores (0.0–1.0) and boolean flags.

### 2. Governance Agent (Optional / Advisory)
The reasoning layer that interprets the Rule Engine's outputs.
- **Input**: Aggregated, sanitized metrics (JSON).
- **Function**: Generates human-readable explanations ("Why was this dataset flagged?") and suggests remediation strategies ("Increase noise parameters for 'age' column").
- **Constraints**: 
  - **Read-Only**: Cannot modify data or update policy rules.
  - **Sanitized**: Receives only pre-computed statistics, never row-level data.

### 3. Audit Logger
The compliance layer.
- **Records**: Timestamps, metric values, risk assessments (LOW/WARNING/CRITICAL), and raw LLM prompts/responses.
- **Purpose**: Ensures every governance decision is traceable and reproducible.

## 🤖 LLM-Powered Governance Agent (Optional)

The system is designed to work fully deterministically. However, enabling the optional LLM Provider adds a layer of explainability.

**Role of the LLM:**
- The LLM acts as an **analyst**, not a judge. 
- It interprets scores (e.g., "Privacy Score: 0.72") and explains the implications ("High risk of linkage attacks due to unique attribute combinations").
- It recommends corrective actions (e.g., "Regenerate with higher differential privacy constraints").

**Technical Implementation:**
- **Default Backend**: Local execution via **Ollama** (e.g., Llama 3, Phi-3) to ensure data sovereignty.
- **Optional Backends**: Support for Anthropic/OpenAI APIs for cases where local compute is insufficient.

> **⚠️ CRITICAL**: The LLM is **advisory, not authoritative**. It cannot override hard containment rules (e.g., "Reject if PII detected").

## 🔒 Security & Privacy Guarantees

This system is built for regulated environments where data leakage is unacceptable.

1. **No Raw Data Storage**: The agent operates on statistical profiles and transient in-memory objects. **Original datasets are used solely for generating statistical profiles in memory.** Raw data is processed in-stream and discarded.
2. **LLM Isolation**: 
   - Uses a "Zero-Trust" approach to the LLM.
   - **No PII Transmission**: The LLM *never* sees a single row of user data.
   - **No Execution**: The LLM outputs text/JSON recommendations; it cannot execute code or SQL.
3. **Auditability**: All interactions, including the exact prompt sent to the LLM and its raw response, are strictly logged. **Note**: All logged LLM prompts and responses are sanitized. No raw data, identifiers, or PII are ever stored.

## 📝 Example Output

When evaluating a dataset, the agent produces a structured report:

```json
{
  "eval_id": "eval_20231027_001",
  "risk_level": "CRITICAL",
  "decision_basis": "policy_threshold_violation",
  "metrics": {
    "privacy_score": 0.65,
    "utility_score": 0.92,
    "leakage_risk_level": "HIGH",
    "semantic_violations": 0
  },
  "governance_interpretation": {
    "summary": "The dataset preserves utility well but fails privacy checks due to high near-duplicate rates.",
    "recommendation": "REGENERATE with increased noise.",
    "risk_assessment": "3.4% of synthetic rows are identical to training samples, posing a membership inference risk.",
    "strategy": {
      "action": "adjust_noise",
      "target_columns": ["zip_code", "birth_date"]
    }
  }
}
```

## 🚫 Non-Goals

To stay production-ready and focused, this system explicitly avoids:

- **Perfect Privacy Guarantees**: While it detects leakage, it does not mathematically prove differential privacy guarantees unless the upstream generator provides them.
- **Automated Data Fixing**: The agent detects issues and recommends fixes but does not silently modify data to "make it pass."
- **Autonomous Operation**: The system is a tool for humans; it does not deploy models or publish data without explicit pipeline configuration.
- **Regulatory Compliance**: This tool aids in compliance (GDPR/CCPA) but is not a replacement for legal counsel or Data Protection Officer review.

## 📦 Installation & Usage

### Installation
```bash
pip install -e .
```

### Basic Usage

```python
from governance_core import RuleEngine, GovernanceAgent

# 1. Deterministic Evaluation (original_df used for transient profiling only)
engine = RuleEngine()
metrics = engine.evaluate_synthetic_data(synthetic_df, original_df)

# 2. (Optional) LLM Interpretation
agent = GovernanceAgent(provider_type="ollama", provider_kwargs={"model": "phi3"})
interpretation = agent.interpret_metrics(metrics)

print(f"Risk Level: {interpretation.get('risk_level', 'UNKNOWN')}")
print(f"Explanation: {interpretation['justification']}")
```
