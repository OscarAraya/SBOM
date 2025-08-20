# Being used
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

df = pd.read_csv('tensorflow.csv')

# Convierte published_at a datetime y se ordena por fecha de liberación
df['release_date'] = pd.to_datetime(df['published_at'], errors='coerce')
df.sort_values('release_date', inplace=True)

# Categorize risk levels based on CVSS scores
def categorize_risk(cvss_score):
    if cvss_score >= 9.0:
        return 'Crítico'
    elif cvss_score >= 7.0:
        return 'Alto'
    elif cvss_score >= 4.0:
        return 'Medio'
    else:
        return 'Bajo'

df['Risk_Level'] = df['base_score'].apply(categorize_risk)

# Escenario sin SBOM
df['Risk_Level_No_SBOM'] = df['Risk_Level']

# Función para determinar la efectividad de SBOM según la antigüedad de liberación
def get_sbom_effect_factor(release_date, patch_availability=True):
    years_since_release = (pd.to_datetime('today') - release_date).days / 365
    if patch_availability:
        if years_since_release > 2:
            return 0.90  # Se asume: Las versiones anteriores tienen más parches disponibles
        elif years_since_release > 1:
            return 0.75
        else:
            return 0.50  # Versiones recientes posiblemente carezcan de correcciones disponibles
    else:
        return 0.40  # Si no hay ningún parche disponible, se reduce el impacto de SBOM

# Función para simular la probabilidad de disponibilidad del parche en función de la antigüedad de la vulnerabilidad
def has_patch_available(release_date):
    return np.random.rand() < min(0.9, (pd.to_datetime('today') - release_date).days / 1000)

# Función para aplicar diferentes modelos SBOM
def get_sbom_model_factor(model='basic'):
    if model == 'basic':
        return np.random.uniform(0.3, 0.4)
    elif model == 'advanced':
        return np.random.uniform(0.5, 0.7)
    return 0  # Caso sin SBOM

# Función para simular dinámicamente el efecto SBOM
def simulate_sbom_effect(risk, release_date, model='advanced'):
    patch_available = has_patch_available(release_date)
    sbom_factor = get_sbom_effect_factor(release_date, patch_availability=patch_available) * get_sbom_model_factor(model)
    
    transition_probs = {
        'Crítico': [sbom_factor * 0.85, 1 - sbom_factor * 0.85],
        'Alto': [sbom_factor * 0.75, 1 - sbom_factor * 0.75],
        'Medio': [sbom_factor * 0.65, 1 - sbom_factor * 0.65],
        'Bajo': [1.0, 0.0]
    }
    
    if risk in transition_probs:
        return np.random.choice(['Bajo', 'Medio', 'Alto', 'Crítico'][:len(transition_probs[risk])], 
                                p=transition_probs[risk])
    return risk

# Aplicar el efecto SBOM considerando la disponibilidad de parches
df['Risk_Level_SBOM'] = df.apply(lambda row: simulate_sbom_effect(row['Risk_Level'], row['release_date'], model='advanced'), axis=1)

# Asegúrarse que el tag_name esté ordenado por fecha de lanzamiento
df_sorted = df[['tag_name', 'release_date']].drop_duplicates().sort_values('release_date')
df['tag_name'] = pd.Categorical(df['tag_name'], categories=df_sorted['tag_name'], ordered=True)

# Se define el orden de nivel de riesgo
risk_levels = ['Crítico', 'Alto', 'Medio', 'Bajo']

# Se agregan datos y se ordenan en el orden correcto
heatmap_data_no_sbom = pd.crosstab(df['tag_name'], df['Risk_Level_No_SBOM'])
heatmap_data_no_sbom = heatmap_data_no_sbom.reindex(columns=risk_levels, fill_value=0)

heatmap_data_sbom = pd.crosstab(df['tag_name'], df['Risk_Level_SBOM'])
heatmap_data_sbom = heatmap_data_sbom.reindex(columns=risk_levels, fill_value=0)

# Visualización
fig, axes = plt.subplots(1, 2, figsize=(18, 8), sharey=True)

sns.heatmap(heatmap_data_no_sbom, annot=True, cmap='Reds', ax=axes[0], fmt=".0f")
axes[0].set_title('Niveles de riesgo por Release (No SBOM)', fontsize=14)
axes[0].set_ylabel("Versión", fontsize=12)
axes[0].set_xlabel("Nivel de riesgo No SBOM", fontsize=12)

sns.heatmap(heatmap_data_sbom, annot=True, cmap='Greens', ax=axes[1], fmt=".0f")
axes[1].set_title('Niveles de riesgo por Release  (SBOM)', fontsize=14)
axes[1].set_ylabel("Versión", fontsize=12)
axes[1].set_xlabel("Nivel de riesgo SBOM", fontsize=12)

plt.tight_layout()
plt.show()