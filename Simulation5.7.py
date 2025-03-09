import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# 1. Load the data
df = pd.read_csv("Data.csv")

# 2. Convert published_at to datetime
df["published_at"] = pd.to_datetime(df["published_at"])

# 3. Filter out invalid rows (if necessary)
df = df[df['base_score'] > 0]

# 4. Map base_score to incident probabilities (No SBOM)
df['incident_prob_no_sbom'] = pd.cut(
    df['base_score'],
    bins=[0, 3.9, 6.9, 8.9, 10.0],   # CVSS ranges
    labels=[0.10, 0.30, 0.60, 0.80]  # Probabilities
).astype(float)

# 5. Simulate incidents (No SBOM)
np.random.seed(42)  # For reproducibility
df['incident_occurred_no_sbom'] = (
    np.random.rand(len(df)) < df['incident_prob_no_sbom']
)

# 6. Aggregate incidents by release (No SBOM)
incidents_by_release_no_sbom = (
    df.groupby('tag_name')['incident_occurred_no_sbom']
      .sum()  # Sum of True=1
      .astype(int)
)

# 7. Map base_score to incident probabilities (With SBOM)
df['incident_prob_sbom'] = pd.cut(
    df['base_score'],
    bins=[0, 3.9, 6.9, 8.9, 10.0],   # same CVSS ranges
    labels=[0.05, 0.15, 0.40, 0.60]  # reduced probabilities
).astype(float)

# 8. Simulate incidents (With SBOM)
np.random.seed(42)
df['incident_occurred_sbom'] = (
    np.random.rand(len(df)) < df['incident_prob_sbom']
)

# 9. Aggregate incidents by release (With SBOM)
incidents_by_release_sbom = (
    df.groupby('tag_name')['incident_occurred_sbom']
      .sum()
      .astype(int)
)

# 10. Combine both aggregates into a single DataFrame for the heatmap
heatmap_data = pd.DataFrame({
    'No SBOM': incidents_by_release_no_sbom,
    'With SBOM': incidents_by_release_sbom
})

# 11. Get earliest publish date per release
date_per_release = df.groupby("tag_name")["published_at"].min()

# 12. Merge date info, sort by published_at, then remove it
heatmap_data = heatmap_data.join(date_per_release)
heatmap_data.sort_values("published_at", inplace=True)
heatmap_data.drop(columns="published_at", inplace=True)

# 13. Create the heatmap
plt.figure(figsize=(12, 8))  # Larger figure for readability
sns.set(font_scale=1.1)      # Slightly larger font

ax = sns.heatmap(
    heatmap_data,
    annot=True,             # Show incident counts in each cell
    fmt="d",                # Integer formatting (no scientific notation)
    cmap="Reds",            # Color palette
    linewidths=0.5,         # Thin lines between cells
    cbar_kws={"label": "Number of Incidents"}
)

ax.set_xlabel("Scenario")
ax.set_ylabel("Release Tag")
ax.set_title("Security Incidents Over Time: With vs. Without SBOM")

# Rotate axis labels if needed
plt.xticks(rotation=0)   # Keep 'No SBOM' / 'With SBOM' horizontal
plt.yticks(rotation=0)   # Keep release tags horizontal

plt.tight_layout()
plt.show()
