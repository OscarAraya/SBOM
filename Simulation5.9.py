import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# Load data from CSV file with headers
df = pd.read_csv('Data.csv')

# Convert published_at to datetime and sort by release date
df['release_date'] = pd.to_datetime(df['published_at'], errors='coerce')
df.sort_values('release_date', inplace=True)

# Categorize risk levels based on CVSS scores
def categorize_risk(cvss_score):
    if cvss_score >= 9.0:
        return 'Critical'
    elif cvss_score >= 7.0:
        return 'High'
    elif cvss_score >= 4.0:
        return 'Medium'
    else:
        return 'Low'

df['Risk_Level'] = df['base_score'].apply(categorize_risk)

# Scenario Without SBOM
df['Risk_Level_No_SBOM'] = df['Risk_Level']

# Function to determine SBOM effectiveness based on release age
def get_sbom_effect_factor(release_date):
    years_since_release = (pd.to_datetime('today') - release_date).days / 365
    if years_since_release > 2:
        return 0.85  # Older releases have better patch availability
    elif years_since_release > 1:
        return 0.75
    else:
        return 0.65  # Recent releases have less documented fixes

# Function to apply different SBOM models
def get_sbom_model_factor(model='basic'):
    if model == 'basic':
        return np.random.uniform(0.3, 0.4)
    elif model == 'advanced':
        return np.random.uniform(0.5, 0.7)
    return 0  # No SBOM case

# Adjusted function to simulate SBOM effect dynamically
def simulate_sbom_effect(risk, release_date, model='basic'):
    sbom_factor = get_sbom_effect_factor(release_date) * get_sbom_model_factor(model)
    
    transition_probs = {
        'Critical': [sbom_factor * 0.85, 1 - sbom_factor * 0.85],
        'High': [sbom_factor * 0.75, 1 - sbom_factor * 0.75],
        'Medium': [sbom_factor * 0.65, 1 - sbom_factor * 0.65],
        'Low': [1.0, 0.0],
    }
    
    if risk in transition_probs:
        return np.random.choice(['Low', 'Medium', 'High', 'Critical'][:len(transition_probs[risk])], 
                                p=transition_probs[risk])
    return risk

# Apply SBOM effect
df['Risk_Level_SBOM'] = df.apply(lambda row: simulate_sbom_effect(row['Risk_Level'], row['release_date'], model='advanced'), axis=1)

# Ensure tag_name is ordered by release_date
df_sorted = df[['tag_name', 'release_date']].drop_duplicates().sort_values('release_date')
df['tag_name'] = pd.Categorical(df['tag_name'], categories=df_sorted['tag_name'], ordered=True)

# Define risk level order
risk_levels = ['Critical', 'High', 'Medium', 'Low']

# Aggregate data and ensure correct order
heatmap_data_no_sbom = pd.crosstab(df['tag_name'], df['Risk_Level_No_SBOM'])
heatmap_data_no_sbom = heatmap_data_no_sbom.reindex(columns=risk_levels, fill_value=0)

heatmap_data_sbom = pd.crosstab(df['tag_name'], df['Risk_Level_SBOM'])
heatmap_data_sbom = heatmap_data_sbom.reindex(columns=risk_levels, fill_value=0)

# Visualization
fig, axes = plt.subplots(1, 2, figsize=(16, 8), sharey=True)

sns.heatmap(heatmap_data_no_sbom, annot=True, cmap='Reds', ax=axes[0], fmt=".0f")
axes[0].set_title('Risk Levels per Release (No SBOM)')
axes[0].set_ylabel("Tag Name (Ordered by Release Date)")

sns.heatmap(heatmap_data_sbom, annot=True, cmap='Greens', ax=axes[1], fmt=".0f")
axes[1].set_title('Risk Levels per Release (With SBOM)')
axes[1].set_ylabel("")

plt.tight_layout()
plt.show()
