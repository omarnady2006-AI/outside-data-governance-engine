# Leakage Detection Metrics Reference

This document details the quantitative metrics used by the **Rule Engine** to evaluate synthetic data privacy, utility, and statistical fidelity.

All metrics are computed **deterministically** and are invariant to the specific LLM used for interpretation.

---

## 1. Statistical Fidelity Metrics
*Ensures the synthetic data distribution matches the original data.*

### 1.1 Kullback-Leibler (KL) Divergence
Measures how one probability distribution (synthetic) differentiates from a second, reference probability distribution (original).

- **Type**: Column-univariate
- **Range**: $[0, \infty)$
- **Ideal**: $0.0$ (Indentical distributions)
- **Threshold**: $> 0.1$ indicates drift; $> 0.5$ indicates severe mismatch.
- **Computation**: Bin continuous variables; categorical variables use frequency masses.

### 1.2 Wasserstein Distance (Earth Mover's Distance)
Measures the minimum "work" needed to transform the synthetic distribution into the original distribution.

- **Type**: Column-univariate (Continuous)
- **Range**: $[0, \infty)$
- **Ideal**: $0.0$
- **Advantages**: More robust than KL divergence for disjoint distributions.

### 1.3 Correlation Matrix Distance (Frobenius Norm)
Measures how well the pairwise correlations between columns are preserved.

- **Formula**: $||Corr_{syn} - Corr_{orig}||_F$
- **Range**: $[0, \sqrt{N^2}]$ where N is number of columns.
- **Ideal**: $0.0$
- **Interpretation**: Higher values indicate that relationships between variables (e.g., age vs. income) have been distorted.

---

## 2. Privacy Risk Metrics
*Quantifies the risk of re-identification or information leakage.*

### 2.1 Near-Duplicate Rate
The percentage of synthetic records that are identical (or effectively identical) to records in the original training data.

- **Type**: Row-level
- **Formula**: $\frac{|S \cap O|}{|S|}$ where $S$ is synthetic set, $O$ is original set.
- **Threshold**: 0% (Strict privacy), < 1% (Low risk).
- **Risk**: Direct memorization of training samples.

### 2.2 Distance to Closest Record (DCR)
Measures the Euclidean distance of each synthetic record to its nearest neighbor in the real dataset.

- **Metric**: 5th percentile of the DCR distribution.
- **Interpretation**: If the 5th percentile is extremely small (close to 0), the synthetic data is "hugging" real data points too closely, creating a privacy risk.

### 2.3 Membership Inference Risk (Estimated)
Estimates the vulnerability to Membership Inference Attacks (MIA), where an attacker tries to determine if a specific record was in the training set.

- **Proxy Metric**:AUC score of a shadow classifier trained to distinguish "members" (training data) from "non-members" (holdout data) based on the synthetic data generator's outputs.
- **Range**: $[0.5, 1.0]$
- **Ideal**: $0.5$ (Random guessing - Perfect Privacy)
- **Threshold**: $> 0.6$ indicates detectable leakage.

---

## 3. Utility Preservation Metrics
*Measures how well the synthetic data performs on downstream ML tasks.*

### 3.1 Predictive Performance Ratio (PPR)
Compares the accuracy (or F1/RMSE) of a model trained on synthetic data vs. real data.

- **Formula**: $Score_{synthetic} / Score_{real}$
- **Range**: $[0, \sim 1.0]$
- **Ideal**: $1.0$ (Synthetic data yields same model performance as real data).
- **Threshold**: $< 0.85$ indicates significant utility loss.

### 3.2 Feature Importance Consistency
Measures if the same features drive predictions in both synthetic and real data models.

- **Metric**: Rank-Order Correlation (Spearman) of feature importance vectors.
- **Range**: $[-1, 1]$
- **Ideal**: $1.0$ (Same features are important in both).

---

## 4. Semantic Integrity Metrics
*Ensures data follows business rules and logic.*

### 4.1 Schema Validity
Checks conformance to defined types, ranges, and allowed values (enums).
- **Output**: Count of invalid cells.

### 4.2 Logical Constraints
Checks multi-column logic (e.g., `Start Date <= End Date`, `Age >= 18` if `Status == 'Adult'`).
- **Output**: Count of invalid rows.
