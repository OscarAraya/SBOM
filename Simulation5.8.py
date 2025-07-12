import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# Load the dataset
df_real = pd.read_csv("tensorflow.csv")

# Show the column names to identify the correct date and severity fields
df_real.columns.tolist()

# Use correct date column
df_real['published_at'] = pd.to_datetime(df_real['published_at'], errors='coerce')
df_real = df_real.dropna(subset=['published_at'])
df_real = df_real.sort_values('published_at').reset_index(drop=True)

# Create synthetic release numbers
df_real['release'] = pd.qcut(df_real.index, q=10, labels=False) + 1
n_releases = df_real['release'].max()

# Assign fix releases
df_real['fix_sbom'] = df_real['release'] + 1
df_real['fix_sbom'] = df_real['fix_sbom'].apply(lambda x: min(x, n_releases))

np.random.seed(42)
df_real['fix_nosbom'] = df_real['release'] + np.random.choice([2, 3, 4], size=len(df_real))
df_real['fix_nosbom'] = df_real['fix_nosbom'].apply(lambda x: x if x <= n_releases else None)

# Calculate open vulnerabilities and risk exposure using base_score
sbom_open = []
nosbom_open = []
sbom_risk = []
nosbom_risk = []

for r in range(1, n_releases + 1):
    sbom_open_count = 0
    nosbom_open_count = 0
    sbom_risk_score = 0.0
    nosbom_risk_score = 0.0

    for _, vuln in df_real.iterrows():
        if vuln['release'] <= r:
            if vuln['fix_sbom'] > r:
                sbom_open_count += 1
                sbom_risk_score += vuln.get('base_score', 0)
            if pd.isna(vuln['fix_nosbom']) or vuln['fix_nosbom'] > r:
                nosbom_open_count += 1
                nosbom_risk_score += vuln.get('base_score', 0)

    sbom_open.append(sbom_open_count)
    nosbom_open.append(nosbom_open_count)
    sbom_risk.append(sbom_risk_score)
    nosbom_risk.append(nosbom_risk_score)

# Plot Open Vulnerabilities
releases = list(range(1, n_releases + 1))

plt.figure(figsize=(10, 6))
plt.plot(releases, sbom_open, marker='o', label='With SBOM')
plt.plot(releases, nosbom_open, marker='o', label='Without SBOM')
plt.title("Open Vulnerabilities per Release (TensorFlow Data)")
plt.xlabel("Release Number")
plt.ylabel("Number of Open Vulnerabilities")
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.show()

# Plot Risk Exposure
plt.figure(figsize=(10, 6))
plt.plot(releases, sbom_risk, marker='o', label='With SBOM')
plt.plot(releases, nosbom_risk, marker='o', label='Without SBOM')
plt.title("Risk Exposure per Release (CVSS Base Score Sum)")
plt.xlabel("Release Number")
plt.ylabel("Risk Exposure Score")
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.show()

# Calculate MTTR
def calculate_mttr(df, fix_col):
    durations = df[fix_col] - df['release']
    durations = durations.dropna()
    return durations.mean()

mttr_sbom = calculate_mttr(df_real, 'fix_sbom')
mttr_nosbom = calculate_mttr(df_real, 'fix_nosbom')

mttr_sbom, mttr_nosbom
