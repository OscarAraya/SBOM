# Being used
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

df = pd.read_csv("tensorflow.csv")
df["base_score"] = pd.to_numeric(df["base_score"], errors="coerce")

# Categorizar la severidad según la puntuación CVSS
bins = [0, 4, 7, 9, 10]
labels = ["Critical", "High", "Medium" , "Low"]
df["Severity"] = pd.cut(df["base_score"], bins=bins, labels=labels, include_lowest=True)

# Probabilidades de incidentes
prob_no_sbom = {"Critical": 0.95, "High": 0.80, "Medium": 0.40, "Low": 0.10 }
prob_with_sbom = {"Critical": 0.85, "High": 0.60, "Medium": 0.25, "Low": 0.05}

# Función para simular incidentes
def simulate_incidents(dataframe, prob_mapping, seed=42):
    np.random.seed(seed)
    df_sim = dataframe.copy()
    # Se simula la generacion de un incidente dependiendo de la severidad 
    # Por ejemplo, con un CVE Alto, existe un 80% de chance de que el numero aleatorio sea < 0.80.
    df_sim["Incident"] = [1 if np.random.rand() < prob_mapping.get(sev, 0) else 0 for sev in df_sim["Severity"]]
    return df_sim

# Simular los escenarios
df_no_sbom = simulate_incidents(df, prob_no_sbom)
df_with_sbom = simulate_incidents(df, prob_with_sbom)

# Definir tiempos medios de Reparación
mean_time_no_sbom = {"Critical": 90, "High": 60, "Medium": 30, "Low": 15}
mean_time_with_sbom = {"Critical": 70, "High": 45, "Medium": 20, "Low": 10 }

# Asignar tiempos de Reparación
np.random.seed(42)
df_no_sbom["RemediationTime"] = [
    # Si se reporto como incidente, se realiza el calculo. Se define el tiempo de reparacion dependiendo de la severidad
    # Si no se encuentra la categoria, se utiliza 10 como predeterminado.
    mean_time_no_sbom.get(sev, 10) * (1 + (np.random.rand() - 0.5) * 0.4) if inc else np.nan
    for sev, inc in zip(df_no_sbom["Severity"], df_no_sbom["Incident"])
]
df_with_sbom["RemediationTime"] = [
    # Si no se encuentra la categoria, se utiliza 7 como predeterminado.
    mean_time_with_sbom.get(sev, 7) * (1 + (np.random.rand() - 0.5) * 0.4) if inc else np.nan
    for sev, inc in zip(df_with_sbom["Severity"], df_with_sbom["Incident"])
]

# Calcular métricas clave
total_incidents_no_sbom = df_no_sbom["Incident"].sum()
total_incidents_with_sbom = df_with_sbom["Incident"].sum()
incident_reduction = ((total_incidents_no_sbom - total_incidents_with_sbom) / total_incidents_no_sbom) * 100

print("Reducción de incidentes:", incident_reduction)

MTTR_no_sbom = df_no_sbom[df_no_sbom["Incident"] == 1]["RemediationTime"].mean()
MTTR_with_sbom = df_with_sbom[df_with_sbom["Incident"] == 1]["RemediationTime"].mean()
mttr_improvement = ((MTTR_no_sbom - MTTR_with_sbom) / MTTR_no_sbom) * 100

print("Mejora del MTTR:", mttr_improvement)

fig, axes = plt.subplots(1, 2, figsize=(12, 6))

# Reducción de incidentes
axes[0].bar(["No SBOM", "SBOM"], [total_incidents_no_sbom, total_incidents_with_sbom], color=["red", "green"])
axes[0].set_title("Total de incidentes con o sin SBOM")
axes[0].set_ylabel("Recuento de incidentes")
axes[0].tick_params(axis="both", labelsize=14)
for bar in axes[0].patches:
    height = bar.get_height()
    axes[0].annotate(f"{int(height)}",
                     (bar.get_x() + bar.get_width() / 2, height),
                     ha="center", va="bottom", fontsize=10)

# Comparación MTTR
axes[1].bar(["No SBOM", "SBOM"], [MTTR_no_sbom, MTTR_with_sbom], color=["red", "green"])
axes[1].set_title("Tiempo promedio de Reparación")
axes[1].set_ylabel("Días")
axes[1].tick_params(axis="both", labelsize=14)
for bar in axes[1].patches:
    height = bar.get_height()
    axes[1].annotate(f"{round(height)}",
                     (bar.get_x() + bar.get_width() / 2, height),
                     ha="center", va="bottom", fontsize=10)

plt.tight_layout()
plt.show()