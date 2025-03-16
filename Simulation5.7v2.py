import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# Load the dataset
df = pd.read_csv("Angular.csv")
df["base_score"] = pd.to_numeric(df["base_score"], errors="coerce")

# Categorize severity based on CVSS score
bins = [0, 4, 7, 10]
labels = ["Low", "Medium", "High"]
df["Severity"] = pd.cut(df["base_score"], bins=bins, labels=labels, include_lowest=True)

# Incident probabilities
prob_no_sbom = {"Low": 0.10, "Medium": 0.40, "High": 0.80}
prob_with_sbom = {"Low": 0.05, "Medium": 0.25, "High": 0.60}

# Function to simulate incidents
def simulate_incidents(dataframe, prob_mapping, seed=42):
    np.random.seed(seed)
    df_sim = dataframe.copy()
    df_sim["Incident"] = [1 if np.random.rand() < prob_mapping.get(sev, 0) else 0 for sev in df_sim["Severity"]]
    return df_sim

# Simulate both scenarios
df_no_sbom = simulate_incidents(df, prob_no_sbom)
df_with_sbom = simulate_incidents(df, prob_with_sbom)

# Define mean remediation times
mean_time_no_sbom = {"Low": 15, "Medium": 10, "High": 5}
mean_time_with_sbom = {"Low": 10, "Medium": 7, "High": 3}

# Assign remediation times
np.random.seed(42)
df_no_sbom["RemediationTime"] = [
    mean_time_no_sbom.get(sev, 10) * (1 + (np.random.rand() - 0.5) * 0.4) if inc else np.nan
    for sev, inc in zip(df_no_sbom["Severity"], df_no_sbom["Incident"])
]
df_with_sbom["RemediationTime"] = [
    mean_time_with_sbom.get(sev, 7) * (1 + (np.random.rand() - 0.5) * 0.4) if inc else np.nan
    for sev, inc in zip(df_with_sbom["Severity"], df_with_sbom["Incident"])
]

# Calculate key metrics
total_incidents_no_sbom = df_no_sbom["Incident"].sum()
total_incidents_with_sbom = df_with_sbom["Incident"].sum()
incident_reduction = ((total_incidents_no_sbom - total_incidents_with_sbom) / total_incidents_no_sbom) * 100

MTTR_no_sbom = df_no_sbom[df_no_sbom["Incident"] == 1]["RemediationTime"].mean()
MTTR_with_sbom = df_with_sbom[df_with_sbom["Incident"] == 1]["RemediationTime"].mean()
mttr_improvement = ((MTTR_no_sbom - MTTR_with_sbom) / MTTR_no_sbom) * 100

# Learning metric calculation
learning_threshold = 0.80
learn_fraction_no_sbom = 0.70
learn_fraction_with_sbom = 0.90
meets_threshold_no = learn_fraction_no_sbom >= learning_threshold
meets_threshold_with = learn_fraction_with_sbom >= learning_threshold

# Visualization
fig, axes = plt.subplots(2, 2, figsize=(12, 10))

# Incident Reduction
axes[0, 0].bar(["No SBOM", "With SBOM"], [total_incidents_no_sbom, total_incidents_with_sbom], color=["red", "green"])
axes[0, 0].set_title("Total Incidents with and without SBOM")
axes[0, 0].set_ylabel("Incident Count")

# MTTR Comparison
axes[0, 1].bar(["No SBOM", "With SBOM"], [MTTR_no_sbom, MTTR_with_sbom], color=["red", "green"])
axes[0, 1].set_title("Mean Time to Recovery (MTTR)")
axes[0, 1].set_ylabel("Days")

# Incident Distribution by Severity
severity_counts_no = df_no_sbom[df_no_sbom["Incident"] == 1]["Severity"].value_counts()
severity_counts_with = df_with_sbom[df_with_sbom["Incident"] == 1]["Severity"].value_counts()
bar_width = 0.35
index = np.arange(len(labels))

axes[1, 0].bar(index, severity_counts_no, bar_width, label="No SBOM", color="red")
axes[1, 0].bar(index + bar_width, severity_counts_with, bar_width, label="With SBOM", color="green")
axes[1, 0].set_xticks(index + bar_width / 2)
axes[1, 0].set_xticklabels(labels)
axes[1, 0].set_title("Incident Distribution by Severity")
axes[1, 0].set_ylabel("Incident Count")
axes[1, 0].legend()

# Learning Metric Comparison
axes[1, 1].bar(["No SBOM", "With SBOM"], [learn_fraction_no_sbom * 100, learn_fraction_with_sbom * 100], color=["red", "green"])
axes[1, 1].axhline(y=learning_threshold * 100, color="black", linestyle="dashed", label="Threshold (80%)")
axes[1, 1].set_title("Incident Learning Metric")
axes[1, 1].set_ylabel("Percentage of Incidents Leading to Improvement")
axes[1, 1].legend()

plt.tight_layout()
plt.show()
