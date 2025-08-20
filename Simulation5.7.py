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
    # Por ejemplo, con un CVE Alto, existe un 80% de probabilidad de que el numero aleatorio sea < 0.80.
    df_sim["Incident"] = [1 if np.random.rand() < prob_mapping.get(sev, 0) else 0 for sev in df_sim["Severity"]]
    return df_sim

# Simular los escenarios
df_no_sbom = simulate_incidents(df, prob_no_sbom)
df_with_sbom = simulate_incidents(df, prob_with_sbom)

# Definir tiempos medios de Reparación
mean_time_no_sbom = {"Critical": np.random.randint(25, 76), "High": np.random.randint(40, 101), "Medium": np.random.randint(80, 161), "Low": np.random.randint(80, 161)}
mean_time_with_sbom = {"Critical": np.random.randint(5, 21), "High": np.random.randint(15, 61), "Medium": np.random.randint(50, 151), "Low": np.random.randint(50, 151)}

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

# Reducción de incidentes
plt.figure(figsize=(8, 5))
bars = plt.bar(["No SBOM", "SBOM"], [total_incidents_no_sbom, total_incidents_with_sbom], color=["red", "green"])
plt.ylabel("Recuento de incidentes")
plt.title("Total de incidentes con o sin SBOM")
for bar in bars:
    height = bar.get_height()
    plt.text(bar.get_x() + bar.get_width()/2., height,
             f'{round(height)}',
             ha="center", va="bottom", fontsize=10)
plt.show()

# Comparación MTTR
plt.figure(figsize=(8, 5))
bars = plt.bar(["No SBOM", "SBOM"], [MTTR_no_sbom, MTTR_with_sbom], color=["red", "green"])
plt.ylabel("Días")
plt.title("Tiempo promedio de Reparación")
for bar in bars:
    height = bar.get_height()
    plt.text(bar.get_x() + bar.get_width()/2., height,
             f'{round(height)}',
             ha="center", va="bottom", fontsize=10)
plt.show()