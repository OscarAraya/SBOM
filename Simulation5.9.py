import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# Load data from CSV file with headers
df = pd.read_csv('Data.csv')

def categorize_risk(cvss_score):
    if cvss_score >= 7.0:
        return 'High'
    elif cvss_score >= 4.0:
        return 'Medium'
    else:
        return 'Low'

df['Risk_Level'] = df['base_score'].apply(categorize_risk)


# Scenario Without SBOM
df['Risk_Level_No_SBOM'] = df['Risk_Level']

# Scenario With SBOM - Synthetic improvement
def simulate_sbom_effect(risk):
    if risk == 'High':
        return np.random.choice(['Medium', 'High'], p=[0.7, 0.3])
    elif risk == 'Medium':
        return np.random.choice(['Low', 'Medium'], p=[0.6, 0.4])
    else:
        return 'Low'

df['Risk_Level_SBOM'] = df['Risk_Level'].apply(simulate_sbom_effect)


heatmap_data_no_sbom = pd.crosstab(df['tag_name'], df['Risk_Level_No_SBOM'])
heatmap_data_sbom = pd.crosstab(df['tag_name'], df['Risk_Level_SBOM'])

# Visualization

fig, axes = plt.subplots(1, 2, figsize=(16, 8), sharey=True)

sns.heatmap(heatmap_data_no_sbom, annot=True, cmap='Reds', ax=axes[0])
axes[0].set_title('Risk Levels per Release (No SBOM)')

sns.heatmap(heatmap_data_sbom, annot=True, cmap='Greens', ax=axes[1])
axes[1].set_title('Risk Levels per Release (With SBOM)')

plt.tight_layout()
plt.show()
