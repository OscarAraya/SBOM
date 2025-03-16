import pandas as pd, numpy as np, matplotlib.pyplot as plt, seaborn as sns

# 1. Load the dataset
df = pd.read_csv("Angular.csv")

# Ensure required columns are present
assert {'base_score','tag_name','published_at'}.issubset(df.columns)

# 2. Define incident probability mapping (as discussed earlier)
def get_incident_probability(base_score, sbom=False):
    if base_score <= 3.9:      # Low severity
        p_no, p_sbom = 0.02, 0.01
    elif base_score <= 6.9:    # Medium severity
        p_no, p_sbom = 0.10, 0.05
    elif base_score <= 8.9:    # High severity
        p_no, p_sbom = 0.25, 0.15
    else:                      # Critical severity
        p_no, p_sbom = 0.40, 0.25
    return p_sbom if sbom else p_no

df['incident_prob_no_sbom'] = df['base_score'].apply(lambda s: get_incident_probability(s, sbom=False))
df['incident_prob_sbom']    = df['base_score'].apply(lambda s: get_incident_probability(s, sbom=True))
df['incident_weight'] = df['base_score']  # use base_score as weight for impact

# 3. Run Monte Carlo simulations
num_simulations = 100
results = []
for sim in range(num_simulations):
    np.random.seed(sim)
    # Random draws for each vulnerability in each scenario
    rand_no_sbom = np.random.rand(len(df))
    rand_sbom    = np.random.rand(len(df))
    # Determine if incident occurs (True/False)
    df['incident_occ_no'] = rand_no_sbom < df['incident_prob_no_sbom']
    df['incident_occ_sbom']= rand_sbom    < df['incident_prob_sbom']
    # Compute weighted incidents
    df['inc_weight_no']   = df['incident_weight'] * df['incident_occ_no']
    df['inc_weight_sbom'] = df['incident_weight'] * df['incident_occ_sbom']
    # Aggregate by release
    agg = df.groupby('tag_name').agg({
        'incident_occ_no':'sum', 'incident_occ_sbom':'sum',
        'inc_weight_no':'sum',  'inc_weight_sbom':'sum'
    }).reset_index()
    agg['simulation'] = sim
    results.append(agg)
all_sims_df = pd.concat(results, ignore_index=True)

# 4. Calculate mean and std of incidents per release
summary_df = all_sims_df.groupby('tag_name').agg({
    'incident_occ_no':   ['mean','std'],
    'incident_occ_sbom': ['mean','std'],
    'inc_weight_no':     ['mean','std'],
    'inc_weight_sbom':   ['mean','std']
})
summary_df.columns = ['_'.join(c) for c in summary_df.columns]
summary_df = summary_df.reset_index()
# (Optionally, sort by release date)
date_map = df.groupby('tag_name')['published_at'].min().to_dict()
summary_df['first_release_date'] = summary_df['tag_name'].map(date_map)
summary_df.sort_values('first_release_date', inplace=True)

# 5. Severity categorization for risk levels
def risk_level(score):
    return 'Low' if score <= 3.9 else ('Medium' if score <= 6.9 else 'High')
df['risk_level'] = df['base_score'].apply(risk_level)

# 5a. Tally vulnerabilities by risk level (for heatmap)
vuln_count = df.pivot_table(index='tag_name', columns='risk_level', values='cve_id', aggfunc='count', fill_value=0)

# 5b. Compute risk matrix counts (likelihood vs impact)
def likelihood_cat(p):
    return 'Low' if p < 0.05 else ('Medium' if p < 0.2 else 'High')
df['likelihood_no']  = df['incident_prob_no_sbom'].apply(likelihood_cat)
df['likelihood_sbom']= df['incident_prob_sbom'].apply(likelihood_cat)
risk_matrix_no   = df.pivot_table(index='risk_level', columns='likelihood_no', values='cve_id', aggfunc='count', fill_value=0)
risk_matrix_sbom = df.pivot_table(index='risk_level', columns='likelihood_sbom', values='cve_id', aggfunc='count', fill_value=0)

# 6. Visualization

# Bar chart: Mean incidents per release (No SBOM vs SBOM)
plt.figure(figsize=(10,5))
x = np.arange(len(summary_df))
plt.bar(x - 0.2, summary_df['incident_occ_no_mean'],  width=0.4, label='No SBOM')
plt.bar(x + 0.2, summary_df['incident_occ_sbom_mean'], width=0.4, label='With SBOM')
plt.xticks(x, summary_df['tag_name'], rotation=90)
plt.ylabel(f"Mean Incident Count (n={num_simulations} sims)")
plt.title("Average Incidents per Release: SBOM vs No SBOM")
plt.legend()
plt.tight_layout()
plt.show()

# Heatmap: CVE count by severity per release
plt.figure(figsize=(8,6))
sns.heatmap(vuln_count, cmap="YlOrRd", annot=True, fmt=".0f")
plt.title("Heatmap of Vulnerability Count by Severity and Release")
plt.xlabel("Severity Category"); plt.ylabel("Release")
plt.show()

# Risk matrix heatmaps for No SBOM and SBOM scenarios
fig, axes = plt.subplots(1,2, figsize=(8,6))
sns.heatmap(risk_matrix_no, annot=True, cmap="Blues", fmt=".0f", cbar=False, ax=axes[0])
axes[0].set_title("Risk Matrix (No SBOM)")
axes[0].set_xlabel("Likelihood"); axes[0].set_ylabel("Impact (Severity)")
sns.heatmap(risk_matrix_sbom, annot=True, cmap="Blues", fmt=".0f", cbar=False, ax=axes[1])
axes[1].set_title("Risk Matrix (With SBOM)")
axes[1].set_xlabel("Likelihood"); axes[1].set_ylabel("")  # y-label on first is enough
plt.tight_layout()
plt.show()
