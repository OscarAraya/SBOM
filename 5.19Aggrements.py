import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

df = pd.read_csv("tensorflow.csv")

df['release_date'] = pd.to_datetime(df.get('published_at'), errors='coerce')
if 'tag_name' in df.columns and 'version' not in df.columns:
    df.rename(columns={'tag_name': 'version'}, inplace=True)
if 'artifact_name' not in df.columns:
    raise ValueError("Column 'artifact_name' not found.")

repo_root = "tensorflow"
df['artifact_name'] = df['artifact_name'].astype(str)
df['is_third_party'] = ~df['artifact_name'].str.lower().str.contains(repo_root)

df = df.dropna(subset=['release_date'])
df = df.sort_values('release_date')

third_party_artifacts = (
    df.loc[df['is_third_party'], 'artifact_name']
    .dropna()
    .unique()
)
n_artifacts = len(third_party_artifacts)
if n_artifacts == 0:
    raise ValueError("No third-party artifacts found to simulate agreements.")

# Create agreement pool
rng = np.random.default_rng(42)
n_agreements = max(12, min(60, int(np.ceil(n_artifacts * 0.6))))
agreement_ids = [f"AGR-{i:04d}" for i in range(1, n_agreements+1)]

categories = ["Open Source", "Commercial", "SaaS", "Contractor"]
cat_probs = [0.55, 0.20, 0.15, 0.10]  # Bias toward OSS

agreements_df = pd.DataFrame({
    "agreement_id": agreement_ids,
    "category": rng.choice(categories, size=n_agreements, p=cat_probs),
})

# Set requirements and compliance levels
required_total = rng.integers(8, 26, size=n_agreements)
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

# Map artifacts to agreements
artifact_to_agreement = pd.DataFrame({
    "artifact_name": third_party_artifacts,
    "agreement_id": rng.choice(agreement_ids, size=n_artifacts, replace=True)
})

# Attach agreement_id to each CVE row
df = df.merge(artifact_to_agreement, on='artifact_name', how='left')

# SIMPLIFIED: Direct semi-annual calculation for B.31 metric
df['year'] = df['release_date'].dt.year
df['half'] = np.where(df['release_date'].dt.month <= 6, 'H1', 'H2')

# Agreements active in each half-year period
agreements_by_half = (
    df.loc[df['is_third_party'] & df['agreement_id'].notna(), 
           ['year', 'half', 'agreement_id']]
    .drop_duplicates()
    .merge(agreements_df[['agreement_id', 'b31_pct']], on='agreement_id', how='left')
)

# Calculate average B.31 metric directly by half-year
b31_by_half = (agreements_by_half
               .groupby(['year', 'half'], as_index=False)['b31_pct']
               .mean()
               .rename(columns={'b31_pct': 'b31_pct_avg'})
               .sort_values(['year', 'half']))

# Conteo de vulnerabilidades per version/fecha
third_party_df = df[df['is_third_party']].copy()
vuln_count = (third_party_df
              .groupby('version', as_index=False)['cve_id']
              .count()
              .rename(columns={'cve_id': 'vulnerabilities'}))

release_dates = (df.groupby('version', as_index=False)['release_date'].min())
vuln_count = vuln_count.merge(release_dates, on='version', how='left').sort_values('release_date')

# Reduccion de vulnerabilidades desde terceros
rng = np.random.default_rng(123)
vuln_count['sbom_basic'] = (vuln_count['vulnerabilities'] * (1 - rng.uniform(0.10, 0.30, len(vuln_count)))).astype(int)
vuln_count['sbom_mature'] = (vuln_count['vulnerabilities'] * (1 - rng.uniform(0.30, 0.50, len(vuln_count)))).astype(int)
vuln_count['sbom_advanced'] = (vuln_count['vulnerabilities'] * (1 - rng.uniform(0.50, 0.70, len(vuln_count)))).astype(int)                

# B.31 uplift function
def uplift(series, low, high):
    return np.clip(series + rng.uniform(low, high, size=len(series)) * 100, 0, 100)

# Apply SBOM uplift to B.31 metric
b31_by_half['b31_basic'] = uplift(b31_by_half['b31_pct_avg']/100, 0.03, 0.08)
b31_by_half['b31_mature'] = uplift(b31_by_half['b31_pct_avg']/100, 0.07, 0.15)
b31_by_half['b31_advanced'] = uplift(b31_by_half['b31_pct_avg']/100, 0.12, 0.25)

# Results
print("=== Acuerdos sintéticos (muestra) ===")
print(agreements_df.sample(5, random_state=7))

print("\n=== Métrica B.31 semestral con mejora por SBOM ===")
print(b31_by_half[['year', 'half', 'b31_pct_avg', 'b31_basic', 'b31_mature', 'b31_advanced']])

print("\n=== Vulnerabilidades con escenarios SBOM (primeras 10 filas) ===")
print(vuln_count[['release_date', 'version', 'vulnerabilities', 'sbom_basic', 'sbom_mature', 'sbom_advanced']].head(10))

fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10))
ax1.plot(vuln_count['release_date'], vuln_count['vulnerabilities'], 
         marker='o', color='red', label='Sin SBOM')
ax1.plot(vuln_count['release_date'], vuln_count['sbom_basic'], 
         marker='o', color="blue", linestyle='--', label='SBOM Básico')
ax1.plot(vuln_count['release_date'], vuln_count['sbom_mature'], 
         marker='o', color="green", linestyle='--', label='SBOM Intermedio')
ax1.plot(vuln_count['release_date'], vuln_count['sbom_advanced'], 
         marker='o', color="purple", linestyle='--', label='SBOM Avanzado')
ax1.set_title('Impacto del SBOM en Vulnerabilidades de Terceros')
ax1.set_ylabel('Número de Vulnerabilidades')
ax1.legend()
ax1.grid(True, linestyle='--')

b31_by_half['period'] = pd.to_datetime(
    b31_by_half['year'].astype(str) + 
    np.where(b31_by_half['half'] == 'H1', '-01-01', '-07-01')
)

ax2.plot(b31_by_half['period'], b31_by_half['b31_pct_avg'],
         marker='o', color='black', linewidth=2, label='Sin SBOM')
ax2.plot(b31_by_half['period'], b31_by_half['b31_basic'],
         marker='o', color="blue", linestyle=':', label='SBOM Básico')
ax2.plot(b31_by_half['period'], b31_by_half['b31_mature'],
         marker='o', color="green", linestyle=':', label='SBOM Intermedio')
ax2.plot(b31_by_half['period'], b31_by_half['b31_advanced'],
         marker='o', color="purple", linestyle=':', label='SBOM Avanzado')
ax2.set_title('Evolución de la Métrica B.31 - Seguridad en Acuerdos con Terceros')
ax2.set_ylabel('Porcentaje de Requisitos Abordados')
ax2.set_xlabel('Periodo')
ax2.legend()
ax2.grid(True, linestyle='--')
ax2.set_ylim(0, 100)

plt.tight_layout()
plt.show()