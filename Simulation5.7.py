import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# Load data from CSV file with headers
df = pd.read_csv('Data.csv')

# Data Simulation (CVSS-based Incident Probability)
# Filter valid CVSS scores
df = df[df['base_score'] > 0]

# Map CVSS score to incident probability for scenario WITHOUT SBOM
df['incident_prob_no_sbom'] = pd.cut(
    df['base_score'],
    bins=[0, 3.9, 6.9, 8.9, 10.0],  # CVSS score ranges
    labels=[0.10, 0.30, 0.60, 0.80]  # corresponding probabilities
).astype(float)

# Simulate whether each vulnerability leads to an incident (1 = incident occurs)
np.random.seed(42)  # for reproducibility
df['incident_occured_no_sbom'] = np.random.rand(len(df)) < df['incident_prob_no_sbom']

# Aggregate incident counts per release (tag_name)
incidents_by_release = df.groupby('tag_name')['incident_occured_no_sbom'].sum()
print(incidents_by_release.head(5))


# SBOM Impact Simulation (Reduced Incident Probability)
# Map CVSS score to incident probability for scenario WITH SBOM
df['incident_prob_sbom'] = pd.cut(
    df['base_score'],
    bins=[0, 3.9, 6.9, 8.9, 10.0],
    labels=[0.05, 0.15, 0.30, 0.40]  # lowered probabilities
).astype(float)

# Simulate incident occurrence with SBOM in place
df['incident_occured_sbom'] = np.random.rand(len(df)) < df['incident_prob_sbom']

# Aggregate incident counts per release for both scenarios
incidents_by_release = df.groupby('tag_name')[['incident_occured_no_sbom','incident_occured_sbom']].sum().astype(int)
print(incidents_by_release.head(5))


# Visualization
# Prepare matrix: rows = Release, cols = Scenario (No SBOM vs SBOM)
heatmap_data = incidents_by_release.rename(columns={
    'incident_occured_no_sbom': 'No SBOM', 
    'incident_occured_sbom': 'With SBOM'
})
sns.heatmap(heatmap_data, annot=True, cmap="Reds")

# Trend Analysis
# Ensure releases are in chronological order by release date
df['release_date'] = pd.to_datetime(df['published_at'])
incidents_by_date = df.groupby('release_date')[['incident_occured_no_sbom','incident_occured_sbom']].sum().sort_index()

# Prepare time series data
dates = incidents_by_date.index
incidents_no_sbom = incidents_by_date['incident_occured_no_sbom']
incidents_sbom = incidents_by_date['incident_occured_sbom']

# Plot the trend over time
import matplotlib.pyplot as plt
plt.plot(dates, incidents_no_sbom, label='Without SBOM', marker='o')
plt.plot(dates, incidents_sbom, label='With SBOM', marker='o')
plt.xlabel('Release Date')
plt.ylabel('Number of Incidents')
plt.title('Security Incidents Over Time: With vs. Without SBOM')
plt.legend()
plt.show()


