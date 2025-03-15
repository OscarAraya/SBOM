"""
simulate_incidents.py

Simulate security incidents for each vulnerability in a real dataset (e.g. TensorFlowData.csv),
comparing scenarios with and without SBOM usage.

References:
 - ISO/IEC 27001:2022 (Risk-based approach to security controls)
 - ISO/IEC 27004:2016 (Security metrics and measurement)
 - Example sources for SBOM effectiveness: 
   [Peeters, 2023], [Checkmarx, 2023], [Balbix, 2023].
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# 1. Load the real dataset (TensorFlowData.csv).
#    Assumption: The CSV has columns like ["Release","Vulnerability","CVSS","Description",...]
#    Adjust the column names as needed for your actual data.
df = pd.read_csv("TensorFlowData.csv")

# 2. Convert the CVSS scores into severity bins if not already binned.
#    (High-level example bins: 0-4=Low, 4-7=Medium, 7-10=High).
#    You can adjust the bins and labels based on your data.
bins = [0, 4, 7, 10]
labels = ["Low", "Medium", "High"]
df["Severity"] = pd.cut(df["base_score"], bins=bins, labels=labels, include_lowest=True)

# 3. Assign a base incident probability for each severity WITHOUT SBOM.
#    This is a simplified assumption; adjust to reflect real-world rates or use EPSS-based data.
prob_mapping_without_sbom = {
    "Low": 0.10,     # 10% chance leads to incident
    "Medium": 0.40,  # 40% chance leads to incident
    "High": 0.80     # 80% chance leads to incident
}

# 4. Assign a reduced incident probability WITH SBOM.
#    We assume SBOM usage lowers each severity's exploitation probability.
prob_mapping_with_sbom = {
    "Low": 0.05,     # from 10% down to 5%
    "Medium": 0.25,  # from 40% down to 25%
    "High": 0.60     # from 80% down to 60%
}

# 5. Simulate incidents.
#    We'll do a single pass for demonstration, but you can wrap this in Monte Carlo if desired.
np.random.seed(42)  # for reproducibility

def simulate_incidents(df, prob_mapping):
    """Return a DataFrame containing whether each vuln was 'Incident=1' or not 'Incident=0'."""
    # Copy original
    df_sim = df.copy()
    # Assign random "incident" outcome based on severity probabilities
    incident_flags = []
    for severity in df_sim["Severity"]:
        base_prob = prob_mapping.get(severity, 0.0)
        # random draw for each vulnerability
        incident_occurred = 1 if np.random.rand() < base_prob else 0
        incident_flags.append(incident_occurred)
    df_sim["Incident"] = incident_flags
    return df_sim

df_no_sbom = simulate_incidents(df, prob_mapping_without_sbom)
df_sbom = simulate_incidents(df, prob_mapping_with_sbom)

# 6. Count total incidents (or group by Release for a more granular view).
incidents_without_sbom = df_no_sbom["Incident"].sum()
incidents_with_sbom = df_sbom["Incident"].sum()

print(f"Total Incidents Without SBOM: {incidents_without_sbom}")
print(f"Total Incidents With SBOM:    {incidents_with_sbom}")

# 7. Optionally group by release and create a bar chart or heatmap to visualize incidents.
incidents_by_release_no_sbom = df_no_sbom.groupby("tag_name")["Incident"].sum()
incidents_by_release_sbom = df_sbom.groupby("tag_name")["Incident"].sum()

releases = incidents_by_release_no_sbom.index
vals_no_sbom = incidents_by_release_no_sbom.values
vals_sbom = incidents_by_release_sbom.values

# Plot bar chart comparing the sum of incidents per release side-by-side.
plt.figure(figsize=(10, 6))
index = np.arange(len(releases))
width = 0.35

plt.bar(index, vals_no_sbom, width, label='No SBOM')
plt.bar(index + width, vals_sbom, width, label='With SBOM')

plt.xlabel('Release')
plt.ylabel('Number of Incidents')
plt.title('Simulated Incidents by Release: No SBOM vs With SBOM')
plt.xticks(index + width/2, releases, rotation=90)
plt.legend()
plt.tight_layout()
plt.show()
