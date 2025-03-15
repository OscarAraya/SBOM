import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from packaging import version

# 1. Load Data
df = pd.read_csv('TensorFlowData.csv')
df['published_at'] = pd.to_datetime(df['published_at'])
df.sort_values('published_at', inplace=True)

# 2. Parse Tag Names & Classify Releases
df['base_tag'] = (
    df['tag_name']
    .str.replace('^v', '', regex=True)
    .str.replace(r'-rc\d*', '', regex=True)
    .str.replace(r'-beta\d*', '', regex=True)
    .str.strip()
)

def parse_semver(tag_str):
    try:
        return version.parse(tag_str)
    except:
        return None

df['semver'] = df['base_tag'].apply(parse_semver)
df['release_type'] = df['prerelease'].apply(lambda x: 'Prerelease' if x == 1 else 'Production')

# 3. Define Simulation Function
def simulate_vulnerabilities(dataframe, group_field='tag_name'):
    df_sorted = dataframe.sort_values('published_at')
    non_sbom_counts = []
    sbom_counts = []
    seen = set()

    for release_val, group in df_sorted.groupby(group_field):
        vulns = set(group['cve_id'])
        non_sbom_counts.append(len(vulns))
        new_vulns = vulns - seen
        sbom_counts.append(len(new_vulns))
        seen.update(new_vulns)

    return non_sbom_counts, sbom_counts

def percentage_reduction(non_sbom_list, sbom_list):
    if sum(non_sbom_list) == 0:
        return 0
    return (sum(non_sbom_list) - sum(sbom_list)) / sum(non_sbom_list) * 100

# 4. Production-Only Analysis
prod_df = df[df['release_type'] == 'Production'].copy()
non_sbom_prod, sbom_prod = simulate_vulnerabilities(prod_df, 'tag_name')
prod_release_order = (prod_df.drop_duplicates('tag_name')
                      .sort_values('published_at')['tag_name'].tolist())

# 5. Plot Production Releases
x_prod = range(len(prod_release_order))
plt.figure(figsize=(10, 6))
plt.plot(
    x_prod, non_sbom_prod,
    label="Non-SBOM (Production)",
    color='red', marker='o'
)
plt.plot(
    x_prod, sbom_prod,
    label="SBOM (Production)",
    color='blue', marker='o'
)
plt.title("Vulnerability Exposure (Production Releases)")
plt.xlabel("Production Release Index")
plt.ylabel("Vulnerability Count")
plt.legend()

# Show fewer x-axis labels
step = max(1, len(prod_release_order)//10)
ticks_to_show = list(range(0, len(prod_release_order), step))
tick_labels = [prod_release_order[i] for i in ticks_to_show]
plt.xticks(ticks_to_show, tick_labels, rotation=45)
plt.tight_layout()
plt.show()

# Print improvement
prod_reduction = percentage_reduction(non_sbom_prod, sbom_prod)
print(f"[Production] Vulnerability reduction with SBOM: {prod_reduction:.2f}%")

# 6. Prerelease Analysis (Optional)
pre_df = df[df['release_type'] == 'Prerelease'].copy()
if not pre_df.empty:
    non_sbom_pre, sbom_pre = simulate_vulnerabilities(pre_df, 'tag_name')
    pre_release_order = (pre_df.drop_duplicates('tag_name')
                         .sort_values('published_at')['tag_name'].tolist())
    x_pre = range(len(pre_release_order))

    plt.figure(figsize=(10, 6))
    plt.plot(
        x_pre, non_sbom_pre,
        label="Non-SBOM (Prerelease)",
        color='orange', marker='o', linestyle='--'
    )
    plt.plot(
        x_pre, sbom_pre,
        label="SBOM (Prerelease)",
        color='green', marker='o', linestyle='--'
    )
    plt.title("Vulnerability Exposure (Prereleases)")
    plt.xlabel("Prerelease Index")
    plt.ylabel("Vulnerability Count")
    plt.legend()

    step = max(1, len(pre_release_order)//10)
    ticks_to_show = list(range(0, len(pre_release_order), step))
    tick_labels = [pre_release_order[i] for i in ticks_to_show]
    plt.xticks(ticks_to_show, tick_labels, rotation=45)
    plt.tight_layout()
    plt.show()

    pre_reduction = percentage_reduction(non_sbom_pre, sbom_pre)
    print(f"[Prerelease] Vulnerability reduction with SBOM: {pre_reduction:.2f}%")
