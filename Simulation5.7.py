# Not being used
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from scipy.stats import ttest_ind

# Load dataset
df = pd.read_csv("tensorflow.csv")

# Ensure published_at is in datetime format
df['published_at'] = pd.to_datetime(df['published_at'])

# Filter vulnerabilities with CVSS scores
df = df[df['base_score'] > 0]

# Define incident probabilities based on CVSS scores
df['incident_prob_no_sbom'] = pd.cut(
    df['base_score'],
    bins=[0, 3.9, 6.9, 8.9, 10.0],
    labels=[0.10, 0.30, 0.60, 0.80]
).astype(float)

df['incident_prob_sbom'] = pd.cut(
    df['base_score'],
    bins=[0, 3.9, 6.9, 8.9, 10.0],
    labels=[0.05, 0.15, 0.30, 0.40]
).astype(float)

# Adjust probabilities based on exploitability score
df['adjusted_prob_no_sbom'] = df['incident_prob_no_sbom'] + (df['exploitability_score'] / 10) * 0.2
df['adjusted_prob_sbom'] = df['incident_prob_sbom'] - (df['exploitability_score'] / 10) * 0.2

df[['adjusted_prob_no_sbom', 'adjusted_prob_sbom']] = df[['adjusted_prob_no_sbom', 'adjusted_prob_sbom']].clip(0, 1)

# Simulate incident occurrences
df['incident_occured_no_sbom'] = (np.random.rand(len(df)) < df['adjusted_prob_no_sbom']).astype(int)
df['incident_occured_sbom'] = (np.random.rand(len(df)) < df['adjusted_prob_sbom']).astype(int)

# Define Mean Time to Respond (MTTR)
df['mttr_no_sbom'] = np.random.normal(loc=15, scale=3, size=len(df))
df['mttr_sbom'] = np.random.normal(loc=5, scale=2, size=len(df))

# Define Mean Time Between Failures (MTBF)
df['mtbf_no_sbom'] = np.random.normal(loc=30, scale=5, size=len(df))
df['mtbf_sbom'] = np.random.normal(loc=50, scale=7, size=len(df))

# Simulate Incident Recurrence Probability
df['incident_recurrence_prob_no_sbom'] = np.random.choice([0.1, 0.3, 0.5], size=len(df), p=[0.4, 0.4, 0.2])
df['incident_recurrence_prob_sbom'] = df['incident_recurrence_prob_no_sbom'] * 0.3

# Visualization: Incident Probability Distribution
plt.figure(figsize=(10, 6))
plt.hist(df['adjusted_prob_no_sbom'], bins=20, alpha=0.5, label="No SBOM", color="red")
plt.hist(df['adjusted_prob_sbom'], bins=20, alpha=0.5, label="With SBOM", color="green")
plt.xlabel("Incident Probability")
plt.ylabel("Frequency")
plt.title("Incident Probability Distribution: No SBOM vs With SBOM")
plt.legend()
plt.show()

# Visualization: MTTR Comparison
plt.figure(figsize=(10, 6))
plt.hist(df['mttr_no_sbom'], bins=20, alpha=0.5, label="No SBOM (MTTR)", color="red")
plt.hist(df['mttr_sbom'], bins=20, alpha=0.5, label="With SBOM (MTTR)", color="green")
plt.xlabel("Mean Time to Respond (Days)")
plt.ylabel("Frequency")
plt.title("MTTR Comparison: No SBOM vs With SBOM")
plt.legend()
plt.show()

# Visualization: MTBF Comparison
plt.figure(figsize=(10, 6))
plt.hist(df['mtbf_no_sbom'], bins=20, alpha=0.5, label="No SBOM (MTBF)", color="red")
plt.hist(df['mtbf_sbom'], bins=20, alpha=0.5, label="With SBOM (MTBF)", color="green")
plt.xlabel("Mean Time Between Failures (Days)")
plt.ylabel("Frequency")
plt.title("MTBF Comparison: No SBOM vs With SBOM")
plt.legend()
plt.show()

# Statistical comparison
stat_results = {
    "MTTR": ttest_ind(df['mttr_no_sbom'], df['mttr_sbom'], equal_var=False),
    "MTBF": ttest_ind(df['mtbf_no_sbom'], df['mtbf_sbom'], equal_var=False),
}

for key, value in stat_results.items():
    print(f"{key} - T-Statistic: {value.statistic:.4f}, P-Value: {value.pvalue:.4e}")
