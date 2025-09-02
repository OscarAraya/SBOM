import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

df = pd.read_csv("vercel.csv")

df['release_date'] = pd.to_datetime(df.get('published_at'), errors='coerce')
if 'tag_name' in df.columns and 'version' not in df.columns:
    df.rename(columns={'tag_name': 'version'}, inplace=True)
if 'artifact_name' not in df.columns:
    raise ValueError("Column 'artifact_name' not found.")

# Todo aquel artefacto diferente al repo se considera como tercero
repo_root = "next"
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

# Creacion del set de acuerdos
rng = np.random.default_rng(42)
n_agreements = max(12, min(60, int(np.ceil(n_artifacts * 0.6))))
agreement_ids = [f"AGR-{i:04d}" for i in range(1, n_agreements+1)]

categories = ["Open Source", "Commercial", "Contractor"]
cat_probs = [0.55, 0.30, 0.15]  # Probabilidades de seleccion de categorias

agreements_df = pd.DataFrame({
    "agreement_id": agreement_ids,
    "category": rng.choice(categories, size=n_agreements, p=cat_probs),
})

# Se establecen los niveles de cumplimiento de cada categoria
required_total = rng.integers(8, 26, size=n_agreements)
base_rates = []
for cat in agreements_df['category']:
    if cat in ("Commercial"):
        base_rates.append(rng.uniform(0.75, 0.95))
    elif cat == "Open Source":
        base_rates.append(rng.uniform(0.60, 0.90))
    else:  # Contractor
        base_rates.append(rng.uniform(0.65, 0.92))
base_rates = np.array(base_rates)

# Calculo del cumplimiento
addr_total = np.minimum(required_total, np.floor(required_total * base_rates)).astype(int)

agreements_df['required_total'] = required_total
agreements_df['addressed_total'] = addr_total

# Calculo de la metrica B31.
agreements_df['b31_pct'] = 100 * agreements_df['addressed_total'] / agreements_df['required_total']

# Mapeo de los acuerdos a artefactos de manera aleatoria
artifact_to_agreement = pd.DataFrame({
    "artifact_name": third_party_artifacts,
    "agreement_id": rng.choice(agreement_ids, size=n_artifacts, replace=True)
})

# Se mapea el acuerdo con los CVE
df = df.merge(artifact_to_agreement, on='artifact_name', how='left')

# Separacion de fechas a semestral
df['year'] = df['release_date'].dt.year
df['half'] = np.where(df['release_date'].dt.month <= 6, 'H1', 'H2')

# Acuerdos activos en mitades
agreements_by_half = (
    df.loc[df['is_third_party'] & df['agreement_id'].notna(), 
           ['year', 'half', 'agreement_id']]
    .drop_duplicates()
    .merge(agreements_df[['agreement_id', 'b31_pct']], on='agreement_id', how='left')
)
np.random.seed(42)

# Calculo del promedio B.31 semestralmente
b31_by_half = (agreements_by_half
               .groupby(['year', 'half'], as_index=False)['b31_pct']
               .mean()
               .rename(columns={'b31_pct': 'b31_pct_avg'})
               .sort_values(['year', 'half']))

# Conteo de vulnerabilidades por version y fecha
third_party_df = df[df['is_third_party']].copy()
vuln_count = (third_party_df
              .groupby('version', as_index=False)['cve_id']
              .count()
              .rename(columns={'cve_id': 'vulnerabilities'}))

release_dates = (df.groupby('version', as_index=False)['release_date'].min())
vuln_count = vuln_count.merge(release_dates, on='version', how='left').sort_values('release_date')

# Combinacion de datos de vulnerabilidades con metricas B.31
vuln_count['year'] = vuln_count['release_date'].dt.year
vuln_count['half'] = np.where(vuln_count['release_date'].dt.month <= 6, 'H1', 'H2')

# Se agregan las metricas al set de vulnerabilidades
vuln_count = vuln_count.merge(b31_by_half[['year', 'half', 'b31_pct_avg']], 
                              on=['year', 'half'], how='left')

# Se llenan valores vacios con el promedio en general
overall_b31_avg = b31_by_half['b31_pct_avg'].mean()
vuln_count['b31_pct_avg'].fillna(overall_b31_avg, inplace=True)

def calculate_vulnerability_reduction(vulnerabilities, b31_pct, sbom_level):
    # Factor de reduccion en base al nivdel de madurez del SBOM
    base_reductions = {
        'basic': np.random.uniform(0.10, 0.20),
        'mature': np.random.uniform(0.20, 0.30),
        'advanced': np.random.uniform(0.30, 0.40)
    }

    # B.31 como multiplicador de efectividad
    b31_multiplier = 0.5 + (b31_pct / 100)
    
    # Calculo de reduccion
    reduction = base_reductions[sbom_level] * b31_multiplier
    
    # Metodo para asegurarse que la reduccion este en un rango razonable
    reduction = min(reduction, 0.60)
    
    return int(vulnerabilities * (1 - reduction))

# Aplicacion de la reduccion de la vulnerabilidades basado en el cumplimiento de la metrica B.31 y el nivel de SBOM
rng = np.random.default_rng(123)
for idx, row in vuln_count.iterrows():
    vuln_count.at[idx, 'sbom_basic'] = calculate_vulnerability_reduction(
        row['vulnerabilities'], row['b31_pct_avg'], 'basic')
    vuln_count.at[idx, 'sbom_mature'] = calculate_vulnerability_reduction(
        row['vulnerabilities'], row['b31_pct_avg'], 'mature')
    vuln_count.at[idx, 'sbom_advanced'] = calculate_vulnerability_reduction(
        row['vulnerabilities'], row['b31_pct_avg'], 'advanced')

print("Acuerdos sintéticos")
print(agreements_df.sample(5, random_state=7))

print("Número de vulnerabilidades por escenario")
print(vuln_count[['release_date', 'version', 'vulnerabilities', 'sbom_basic', 'sbom_mature', 'sbom_advanced']].head(10))

plt.figure(figsize=(15, 8))

plt.plot(vuln_count['release_date'], vuln_count['vulnerabilities'], 
         marker='o', color='red', label='Sin SBOM')
plt.plot(vuln_count['release_date'], vuln_count['sbom_basic'], 
         marker='o', color="blue", linestyle='--', label='SBOM Básico')
plt.plot(vuln_count['release_date'], vuln_count['sbom_mature'], 
         marker='o', color="green", linestyle='--', label='SBOM Intermedio')
plt.plot(vuln_count['release_date'], vuln_count['sbom_advanced'], 
         marker='o', color="purple", linestyle='--', label='SBOM Avanzado')
plt.title('Impacto del SBOM en Vulnerabilidades de Terceros')
plt.ylabel('Número de Vulnerabilidades')
plt.legend()
plt.grid(True, linestyle='--')

plt.tight_layout()
plt.show()

"""
Se utilizan distintos valores debido al nivel de adopcion y esto depende mucho de las herramientas que se esten utilizando.

https://nios.montana.edu/cyber/products/Impacts%20of%20Software%20Bill%20of%20Materials%20-%20SBOM%20-%20Generation%20on%20Vulnerability%20Detection%20Final%20Version.pdf
https://www.mckinsey.com/capabilities/risk-and-resilience/our-insights/cybersecurity/software-bill-of-materials-managing-software-cybersecurity-risks
https://www.ox.security/sbom-tools-mitigating-supply-chain-risk-driving-compliance/

Basic SBOM Adoption: 10-20% reduction (Blue)
Mature SBOM Adoption: 20-30% reduction (Green)
Advanced SBOM Adoption: 30-40% reduction (Purple)

El objetivo de este apartado es de evaluar el grado de como se aborda la seguridad en los acuerdos con terceros, sugerido por la métrica B.31 de seguridad de acuerdos con terceros del ISO 27004:2016. Esta métrica sugiere una formula en la cual se considere la cantidad de acuerdos y requerimientos acordados entre las partes de ambas organizaciones, sin embargo en este caso es difícil conseguir este tipo de información.
Para este caso de uso se ha conseguido el nombre (artifact_name) y version (artifact_version) del componente vulnerado que se encuentra relacionado al CVE. Con esta información se ha decidido comparar el nombre del componente vulnerado con el nombre del repositorio, en caso que este no encuentre similitudes entre ambos este sera considerado como una biblioteca de terceros, por ende un acuerdo entre ambas partes.

Debido a que el uso del SBOM no es una solución que presente un porcentaje de mejora fijo para todas las organizaciones, se ha considerado tomar en cuenta el nivel de adopción o madurez del proceso de implementación de un SBOM dentro de la organización.

Para esto se han considerado tres categorías, adopción básica, intermedia o avanzada. Para cada uno de estos se ha fijo un rango de porcentajes de reducción. De un 10 a un 30 para el nivel básico, entre un 30 y 50 para el intermedio y finalmente entre un 50 a 70 para el avanzado.

De esta manera se logra observar una posible mejora dependiendo del nivel de adopción e así mismo incentivar una correcta implementación del SBOM dentro la organización.
"""