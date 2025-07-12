# Not being used
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# Load the dataset
df = pd.read_csv("tensorflow.csv")
df["base_score"] = pd.to_numeric(df["base_score"], errors="coerce")
df["published_at"] = pd.to_datetime(df["published_at"], errors='coerce')

# Categorize severity based on CVSS score
bins = [0, 4, 7, 9, 10]
labels = ["Low", "Medium", "High", "Critical"]
df["Severity"] = pd.cut(df["base_score"], bins=bins, labels=labels, include_lowest=True)

# Incident probabilities
prob_no_sbom = {"Critical": 0.95, "High": 0.80, "Medium": 0.40, "Low": 0.10 }
prob_with_sbom = {"Critical": 0.85, "High": 0.60, "Medium": 0.25, "Low": 0.05}

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
mean_time_no_sbom = {"Critical": 90, "High": 60, "Medium": 30, "Low": 15}
mean_time_with_sbom = {"Critical": 70, "High": 45, "Medium": 20, "Low": 10 }

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

# ------------------------
# Dynamic Learning Metric
# ------------------------

def calculate_dynamic_learning_metric(df_no, df_with):
    # Option: Weighted severity impact difference
    severity_weights = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    
    def weighted_impact(df):
        return sum(severity_weights.get(sev, 0) for sev in df[df["Incident"] == 1]["Severity"])

    impact_no_sbom = weighted_impact(df_no)
    impact_with_sbom = weighted_impact(df_with)

    if impact_no_sbom == 0:
        return 1.0  # Perfect

    return 1 - (impact_with_sbom / impact_no_sbom)

learning_metric = calculate_dynamic_learning_metric(df_no_sbom, df_with_sbom)
print(f"Dynamic Learning Metric: {learning_metric * 100:.2f}%")

# ------------------------
# Learning Over Time Plot by Year
# ------------------------

df_no_sbom_sorted = df_no_sbom.sort_values("published_at")
df_with_sbom_sorted = df_with_sbom.sort_values("published_at")

def compute_yearly_learning(df_no, df_with):
    years = sorted(df_no["published_at"].dropna().dt.year.unique())
    yearly_metrics = []
    for year in years:
        df_no_y = df_no[df_no["published_at"].dt.year == year]
        df_with_y = df_with[df_with["published_at"].dt.year == year]
        if len(df_no_y) >= 5 and len(df_with_y) >= 5:  # ensure meaningful metric
            metric = calculate_dynamic_learning_metric(df_no_y, df_with_y)
            yearly_metrics.append((year, metric))
    return yearly_metrics

yearly_learning = compute_yearly_learning(df_no_sbom_sorted, df_with_sbom_sorted)

# Plot
x_vals, y_vals = zip(*yearly_learning)
plt.figure(figsize=(10, 5))
plt.plot(x_vals, [y * 100 for y in y_vals], marker='o')
plt.title("Dynamic Learning Metric Over Time (Yearly)")
plt.xlabel("Year")
plt.ylabel("Learning Metric (%)")
plt.grid(True)
plt.tight_layout()
plt.show()