import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# -------------------------------------------------------------------------
# 1. Load dataset (Adjust file path as needed)
# -------------------------------------------------------------------------
df = pd.read_csv("TensorFlowData.csv")

# Ensure needed columns exist (e.g. 'base_score', 'tag_name', 'published_at')
# This snippet assumes your CSV has columns: 'base_score', 'tag_name', 'published_at'.
# If your column names differ, adjust accordingly.

# -------------------------------------------------------------------------
# 2. Define probability mapping logic
#    You can adjust these to reflect more realistic or research-based values
# -------------------------------------------------------------------------
def get_incident_probability(base_score, sbom=False):
    """
    Returns the probability of an incident for a given CVSS base_score.
    If sbom=True, we assume the probability is lower due to better remediation via SBOM.
    """
    # Example severity cuts:
    #  - [0.0, 3.9] = Low
    #  - [4.0, 6.9] = Medium
    #  - [7.0, 8.9] = High
    #  - [9.0, 10.0] = Critical
    
    # You can tweak these base probabilities:
    if base_score <= 3.9:
        prob_no_sbom = 0.02
        prob_sbom = 0.01
    elif base_score <= 6.9:
        prob_no_sbom = 0.10
        prob_sbom = 0.05
    elif base_score <= 8.9:
        prob_no_sbom = 0.25
        prob_sbom = 0.15
    else:  # 9.0 to 10.0
        prob_no_sbom = 0.40
        prob_sbom = 0.25
    
    return prob_sbom if sbom else prob_no_sbom

# -------------------------------------------------------------------------
# 3. Precompute severity-based probabilities for each row
# -------------------------------------------------------------------------
df['incident_prob_no_sbom'] = df['base_score'].apply(lambda s: get_incident_probability(s, sbom=False))
df['incident_prob_sbom']    = df['base_score'].apply(lambda s: get_incident_probability(s, sbom=True))

# Optional: Weighted approach – using base_score as weight or define custom weighting
# E.g., could do weight = base_score or map severity to numeric weight
df['incident_weight'] = df['base_score']  # using CVSS base_score as the "weight" of the incident

# -------------------------------------------------------------------------
# 4. Multiple Simulation Runs
# -------------------------------------------------------------------------
num_simulations = 100

# We'll store aggregated incident counts by tag_name for each simulation
results_list = []
tag_names = df['tag_name'].unique()

for sim_id in range(num_simulations):
    # Setting a different seed each iteration to get variability
    # Or keep the same seed if you want consistent random draws
    np.random.seed(sim_id + 42)  # offset by sim_id for variety
    
    # Calculate random draws for each row to see if incident occurs
    random_values_no_sbom = np.random.rand(len(df))
    random_values_sbom = np.random.rand(len(df))
    
    df['incident_occurred_no_sbom'] = (random_values_no_sbom < df['incident_prob_no_sbom'])
    df['incident_occurred_sbom']    = (random_values_sbom    < df['incident_prob_sbom'])
    
    # Weighted incidence, e.g., sum base_score for each incident
    df['incident_weight_no_sbom'] = df.apply(
        lambda row: row['incident_weight'] if row['incident_occurred_no_sbom'] else 0.0, axis=1
    )
    df['incident_weight_sbom'] = df.apply(
        lambda row: row['incident_weight'] if row['incident_occurred_sbom'] else 0.0, axis=1
    )
    
    # Aggregate per release
    incidents_by_release_no_sbom = df.groupby('tag_name')['incident_occurred_no_sbom'].sum()
    incidents_by_release_sbom    = df.groupby('tag_name')['incident_occurred_sbom'].sum()
    
    # Weighted aggregates
    weight_by_release_no_sbom = df.groupby('tag_name')['incident_weight_no_sbom'].sum()
    weight_by_release_sbom    = df.groupby('tag_name')['incident_weight_sbom'].sum()
    
    # Store results in a DataFrame so we can average later
    sim_results_df = pd.DataFrame({
        'tag_name': tag_names,
        'simulation_id': sim_id,
        'incidents_no_sbom': incidents_by_release_no_sbom.reindex(tag_names).values,
        'incidents_sbom':    incidents_by_release_sbom.reindex(tag_names).values,
        'weighted_no_sbom':  weight_by_release_no_sbom.reindex(tag_names).values,
        'weighted_sbom':     weight_by_release_sbom.reindex(tag_names).values
    })
    
    results_list.append(sim_results_df)

# Concatenate all simulation results
all_sims_df = pd.concat(results_list, ignore_index=True)

# -------------------------------------------------------------------------
# 5. Compute Mean and Std Dev across simulations
# -------------------------------------------------------------------------
summary_df = all_sims_df.groupby('tag_name').agg({
    'incidents_no_sbom': ['mean', 'std'],
    'incidents_sbom':    ['mean', 'std'],
    'weighted_no_sbom':  ['mean', 'std'],
    'weighted_sbom':     ['mean', 'std']
})

# Flatten multi-level columns for readability
summary_df.columns = ['_'.join(col) for col in summary_df.columns.values]
summary_df.reset_index(inplace=True)

# Merge with date info, if you want chronological ordering
if 'published_at' in df.columns:
    # Get earliest date for each release
    date_map = df.groupby('tag_name')['published_at'].min().to_dict()
    summary_df['published_at'] = summary_df['tag_name'].map(date_map)
    summary_df = summary_df.sort_values('published_at').reset_index(drop=True)

# -------------------------------------------------------------------------
# 6. Example: Visualization of Averages
# -------------------------------------------------------------------------
# Compare average incidents across releases in a bar chart
plt.figure(figsize=(10, 6))
plt.bar(summary_df.index - 0.2, summary_df['incidents_no_sbom_mean'], width=0.4, label='No SBOM')
plt.bar(summary_df.index + 0.2, summary_df['incidents_sbom_mean'], width=0.4, label='With SBOM')
plt.xlabel('Releases (Ordered by Date)')
plt.ylabel('Mean Incident Count (Over {} Simulations)'.format(num_simulations))
plt.title('Comparing Mean Incidents: No SBOM vs With SBOM')
plt.legend()
plt.show()

# -------------------------------------------------------------------------
# 7. Optional: Weighted Incidents Chart
# -------------------------------------------------------------------------
plt.figure(figsize=(10, 6))
plt.bar(summary_df.index - 0.2, summary_df['weighted_no_sbom_mean'], width=0.4, label='No SBOM')
plt.bar(summary_df.index + 0.2, summary_df['weighted_sbom_mean'], width=0.4, label='With SBOM')
plt.xlabel('Releases (Ordered by Date)')
plt.ylabel('Mean Weighted Incidents (Sum of CVSS Scores)'.format(num_simulations))
plt.title('Comparing Weighted Incidents: No SBOM vs With SBOM')
plt.legend()
plt.show()

# -------------------------------------------------------------------------
# 8. Inspect final summary data
# -------------------------------------------------------------------------
print(summary_df.head(10))

