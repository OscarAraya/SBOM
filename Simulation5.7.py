import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# Load data from CSV file with headers
df = pd.read_csv('Data.csv')

# Ensure published_at is in datetime format
df['release_date'] = pd.to_datetime(df['published_at'])

# Data Simulation (CVSS-based Incident Probability)
df = df[df['base_score'] > 0]

df['incident_prob_no_sbom'] = pd.cut(
    df['base_score'],
    bins=[0, 3.9, 6.9, 8.9, 10.0],
    labels=[0.10, 0.30, 0.60, 0.80]
).astype(float)

np.random.seed(42)
df['incident_occured_no_sbom'] = (np.random.rand(len(df)) < df['incident_prob_no_sbom']).astype(int)

df['incident_prob_sbom'] = pd.cut(
    df['base_score'],
    bins=[0, 3.9, 6.9, 8.9, 10.0],
    labels=[0.05, 0.15, 0.30, 0.40]
).astype(float)

df['incident_occured_sbom'] = (np.random.rand(len(df)) < df['incident_prob_sbom']).astype(int)

# Aggregate incidents per release and sort by release date
incidents_by_release = df.groupby(['release_date', 'tag_name'])[['incident_occured_no_sbom','incident_occured_sbom']].sum().astype(int)
incidents_by_release = incidents_by_release.reset_index().sort_values(by='release_date')

# Set 'tag_name' as the index again
df_pivot = incidents_by_release.set_index('tag_name')[['incident_occured_no_sbom', 'incident_occured_sbom']]

plt.figure(figsize=(10, 8))
sns.heatmap(df_pivot, annot=True, cmap="Reds", fmt=".0f")
plt.xlabel('Scenario')
plt.ylabel('Tag Name (Ordered by Release Date)')
plt.title('Security Incidents Over Time: With vs. Without SBOM')
plt.xticks(ticks=[0.5, 1.5], labels=['No SBOM', 'With SBOM'])
plt.yticks(rotation=0)
plt.show()
