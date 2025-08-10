import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# ------------------------------
# Load and prep the vulnerability dataset
# ------------------------------
df = pd.read_csv("tensorflow.csv")

# Normalize/prepare fields
df['release_date'] = pd.to_datetime(df.get('published_at'), errors='coerce')
if 'tag_name' in df.columns and 'version' not in df.columns:
    df.rename(columns={'tag_name':'version'}, inplace=True)
if 'artifact_name' not in df.columns:
    raise ValueError("Expected column 'artifact_name' not found.")

# Identify third-party artifacts (anything that’s not clearly TensorFlow itself)
repo_root = "tensorflow"
df['artifact_name'] = df['artifact_name'].astype(str)
df['is_third_party'] = ~df['artifact_name'].str.lower().str.contains(repo_root)

# Keep rows with dates
df = df.dropna(subset=['release_date'])
df = df.sort_values('release_date')

# ------------------------------
# Metric B.31 context (ISO 27004)
#   B.31 = average % of relevant security requirements addressed in third-party agreements
# ------------------------------

# ### SYNTHETIC AGREEMENTS GENERATION ###
# 1) Build a pool of 3rd-party artifact names
third_party_artifacts = (
    df.loc[df['is_third_party'], 'artifact_name']
      .dropna()
      .unique()
)
n_artifacts = len(third_party_artifacts)
if n_artifacts == 0:
    raise ValueError("No third-party artifacts found to simulate agreements.")

# 2) Create a pool of agreements and categories
rng = np.random.default_rng(42)

# Number of distinct agreements (let’s allow multiple artifacts to map to same agreement)
n_agreements = max(12, min(60, int(np.ceil(n_artifacts * 0.6))))
agreement_ids = [f"AGR-{i:04d}" for i in range(1, n_agreements+1)]

categories = ["Open Source", "Commercial", "SaaS", "Contractor"]
cat_probs = [0.55, 0.20, 0.15, 0.10]  # bias toward OSS in real repos

agreements_df = pd.DataFrame({
    "agreement_id": agreement_ids,
    "category": rng.choice(categories, size=n_agreements, p=cat_probs),
})

# 3) For each agreement, set a number of required requirements and how many are addressed
#    We’ll draw required_total between 8–25; addressed_total depends on a base maturity sampled per agreement.
required_total = rng.integers(8, 26, size=n_agreements)
# Base “address rate” ~60–95%, slightly better for Commercial/SaaS than OSS/Contractor
base_rates = []
for cat in agreements_df['category']:
    if cat in ("Commercial", "SaaS"):
        base_rates.append(rng.uniform(0.75, 0.95))
    elif cat == "Open Source":
        base_rates.append(rng.uniform(0.60, 0.90))
    else:  # Contractor
        base_rates.append(rng.uniform(0.65, 0.92))
base_rates = np.array(base_rates)

addr_total = np.minimum(required_total, np.floor(required_total * base_rates)).astype(int)

agreements_df['required_total'] = required_total
agreements_df['addressed_total'] = addr_total
agreements_df['b31_pct'] = 100 * agreements_df['addressed_total'] / agreements_df['required_total']

# 4) Map artifacts -> agreements (random, many-to-few so agreements repeat across artifacts)
artifact_to_agreement = pd.DataFrame({
    "artifact_name": third_party_artifacts,
    "agreement_id": rng.choice(agreement_ids, size=n_artifacts, replace=True)
})

# 5) Attach agreement_id to each CVE row (only 3rd-party rows will match)
df = df.merge(artifact_to_agreement, on='artifact_name', how='left')

# ------------------------------
# B.31 by reporting period (collect quarterly, report semi-annually)
# We'll compute quarterly averages of % addressed across the UNIQUE agreements that appear in that quarter.
# ------------------------------
df['year_quarter'] = df['release_date'].dt.to_period('Q').astype(str)

# Agreements that were "active" in a quarter = any vuln row with that agreement appears that quarter
agreements_by_q = (
    df.loc[df['is_third_party'] & df['agreement_id'].notna(), ['year_quarter','agreement_id']]
      .drop_duplicates()
      .merge(agreements_df[['agreement_id','b31_pct']], on='agreement_id', how='left')
)

b31_by_q = (agreements_by_q
            .groupby('year_quarter', as_index=False)['b31_pct']
            .mean()
            .rename(columns={'b31_pct':'b31_pct_avg'}))

# Semi-annual reporting: map quarters to H1/H2 and average
b31_by_q['year'] = b31_by_q['year_quarter'].str.slice(0,4).astype(int)
b31_by_q['q'] = b31_by_q['year_quarter'].str.slice(5).str.replace('Q','').astype(int)
b31_by_q['half'] = np.where(b31_by_q['q'].isin([1,2]), 'H1', 'H2')
b31_by_half = (b31_by_q
               .groupby(['year','half'], as_index=False)['b31_pct_avg']
               .mean()
               .sort_values(['year','half']))

# ------------------------------
# Vulnerability counts per version/date (like your current plot)
# ------------------------------
third_party_df = df[df['is_third_party']].copy()
vuln_count = (third_party_df
              .groupby('version', as_index=False)['cve_id']
              .count()
              .rename(columns={'cve_id':'vulnerabilities'}))

release_dates = (df.groupby('version', as_index=False)['release_date']
                   .min())
vuln_count = vuln_count.merge(release_dates, on='version', how='left').sort_values('release_date')

# ------------------------------
# SBOM adoption scenarios (apply to both vulnerabilities and B.31 as “process uplift”)
# ------------------------------
rng = np.random.default_rng(123)

# Reductions in third-party vulnerabilities
vuln_count['sbom_basic']    = (vuln_count['vulnerabilities'] * (1 - rng.uniform(0.10, 0.30, len(vuln_count)))).astype(int)
vuln_count['sbom_mature']   = (vuln_count['vulnerabilities'] * (1 - rng.uniform(0.30, 0.50, len(vuln_count)))).astype(int)
vuln_count['sbom_advanced'] = (vuln_count['vulnerabilities'] * (1 - rng.uniform(0.50, 0.70, len(vuln_count)))).astype(int)

# B.31 uplift (better governance + clearer supplier requirements with SBOM)
def uplift(series, low, high):
    return np.clip(series + rng.uniform(low, high, size=len(series))*100, 0, 100)

b31_by_half['b31_basic']    = uplift(b31_by_half['b31_pct_avg']/100,   0.03, 0.08) * 100
b31_by_half['b31_mature']   = uplift(b31_by_half['b31_pct_avg']/100,   0.07, 0.15) * 100
b31_by_half['b31_advanced'] = uplift(b31_by_half['b31_pct_avg']/100,   0.12, 0.25) * 100

# ------------------------------
# Results (prints)
# ------------------------------
print("=== Agreements (synthetic) sample ===")
print(agreements_df.sample(5, random_state=7))

#print("\n=== Quarterly B.31 (avg % addressed) sample ===")
#print(b31_by_q.head())

print("\n=== Semi-annual B.31 with SBOM uplift ===")
print(b31_by_half[['year','half','b31_pct_avg','b31_basic','b31_mature','b31_advanced']])

print("\n=== Vulnerabilities with SBOM scenarios (first 10 rows) ===")
print(vuln_count[['release_date','version','vulnerabilities','sbom_basic','sbom_mature','sbom_advanced']].head(10))

# ------------------------------
# Charts
# ------------------------------
# 1) Vulnerabilities over time (NO SBOM vs scenarios)
plt.figure(figsize=(11,5))
plt.plot(vuln_count['release_date'], vuln_count['vulnerabilities'], marker='o', color='red', label='No SBOM')
plt.plot(vuln_count['release_date'], vuln_count['sbom_basic'], marker='o', color="blue", linestyle=':', label='SBOM (Básico)')
plt.plot(vuln_count['release_date'], vuln_count['sbom_mature'], marker='o', color="green", linestyle=':', label='SBOM (Maduro)')
plt.plot(vuln_count['release_date'], vuln_count['sbom_advanced'], marker='o', color="purple", linestyle=':', label='SBOM (Avanzado)')
plt.title('Impacto del uso de SBOM en vulnerabilidades de terceros')
plt.xlabel('Fecha Liberación')
plt.ylabel('Número de vulnerabilidades de terceros')
plt.grid(True, linestyle='--', alpha=0.5)
plt.legend()
plt.tight_layout()
plt.show()