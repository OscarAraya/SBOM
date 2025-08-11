# Being used
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# Semilla para la reproducibilidad
np.random.seed(42)

df = pd.read_csv('tensorflow.csv')
# Contar CVE por Release
cve_counts = df.groupby('tag_name').size().reset_index(name='cve_count')
df = df.merge(cve_counts, on='tag_name')

# Definir los sistemas afectados para cada vulnerabilidad
def affected_systems_no_sbom(cvss_score, cve_count):
    # El número base de sistemas afectados aumenta con la gravedad
    if cvss_score >= 9.0:
        base = np.random.randint(4, 6) # Crítico: 4-5 sistemas afectados
    elif cvss_score >= 7.0:
        base = np.random.randint(3, 5) # Alto: 3–4 sistemas
    else:
        base = np.random.randint(1, 4) # Bajo/Medio: 1–3 sistemas
    # Se agrega mayor impacto si la versión del software tiene muchos CVE, asumiento que sea altamente utilizada o esté desactualizada
    extra = cve_count // 5 # +1 sistema por cada 5 CVE en esa versión
    return base + extra

def affected_systems_with_sbom(cvss_score, cve_count):
    # SBOM en uso: se espera que hayan menos sistemas afectados
    if cvss_score >= 9.0:
        base = np.random.randint(2, 4) # Crítico: 2–3 sistemas
    elif cvss_score >= 7.0:
        base = np.random.randint(1, 3) # Alto: 1–2 sistemas
    else:
        base = 1 # Bajo/Medio: 1 sistema posiblemente (impacto mínimo)
    # Se asume que el uso del SBOM evita grandes implementaciones de versiones altamente vulnerables
    extra = 0 # No hay impacto extra en este escenario
    return base + extra

# Se aplican las funciones para obtener el número de sistemas afectados por CVE por escenario
df['Affected_Systems_No_SBOM'] = df.apply(lambda x: affected_systems_no_sbom(x['base_score'], x['cve_count']), axis=1)
df['Affected_Systems_With_SBOM'] = df.apply(lambda x: affected_systems_with_sbom(x['base_score'], x['cve_count']), axis=1)

# Se calcula el panorama de vulnerabilidad (severidad * sistemas afectados) para cada CVE y escenario
df['Vuln_Risk_No_SBOM'] = df['base_score'] * df['Affected_Systems_No_SBOM']
df['Vuln_Risk_With_SBOM'] = df['base_score'] * df['Affected_Systems_With_SBOM']

# Suma de la métrica del panorama de vulnerabilidad para cada escenario
panorama_no_sbom = df['Vuln_Risk_No_SBOM'].sum()
panorama_with_sbom = df['Vuln_Risk_With_SBOM'].sum()

# Simulación del tiempo de detección
def detection_time_no_sbom(cvss_score):
    if cvss_score >= 9.0:
        return np.random.randint(80, 161) # Crítico: 1.3 ~ 5 meses
    elif cvss_score >= 7.0:
        return np.random.randint(90, 171) # Alto: 3 ~ 5.7 meses
    else:
        return np.random.randint(120, 201) # Bajo: 4 ~ 6.7 meses

def detection_time_with_sbom(cvss_score):
    return np.random.randint(10, 26) # Con SBOM: 10 ~ 25 días

df['Detection_Time_No_SBOM'] = df['base_score'].apply(detection_time_no_sbom)
df['Detection_Time_With_SBOM'] = df['base_score'].apply(detection_time_with_sbom)

# Simulación del tiempo de remediación
def remediation_time_no_sbom(cvss_score):
    if cvss_score >= 9.0:
        return np.random.randint(25, 76) # Crítico: 1 ~ 2.5 meses para remediar
    elif cvss_score >= 7.0:
        return np.random.randint(40, 101) # Alto: 1 mes ~ 3.5 meses
    else:
        return np.random.randint(80, 161) # Bajo/Medio: 2.5 ~ 6 meses

def remediation_time_with_sbom(cvss_score):
    if cvss_score >= 9.0:
        return np.random.randint(5, 21) # Crítico: 1 ~ 3 semanas
    elif cvss_score >= 7.0:
        return np.random.randint(15, 61) # Alto: 1 ~ 2 meses
    else:
        return np.random.randint(50, 151) # Bajo/Medio: 1 ~ 5 meses

df['Remediation_Time_No_SBOM'] = df['base_score'].apply(remediation_time_no_sbom)
df['Remediation_Time_With_SBOM'] = df['base_score'].apply(remediation_time_with_sbom)

# Tiempo total desde la divulgación de CVE hasta la remediación (tiempo de detección + reparación)
df['Total_Time_No_SBOM'] = df['Detection_Time_No_SBOM'] + df['Remediation_Time_No_SBOM']
df['Total_Time_With_SBOM'] = df['Detection_Time_With_SBOM'] + df['Remediation_Time_With_SBOM']

# Calculo de tiempos promedio para el resumen
avg_detect_no = df['Detection_Time_No_SBOM'].mean()
avg_detect_with = df['Detection_Time_With_SBOM'].mean()
avg_remed_no = df['Remediation_Time_No_SBOM'].mean()
avg_remed_with = df['Remediation_Time_With_SBOM'].mean()
avg_total_no = df['Total_Time_No_SBOM'].mean()
avg_total_with = df['Total_Time_With_SBOM'].mean()

print(f"Panorama de vulnerabilidad total No SBOM: {panorama_no_sbom:.2f}")
print(f"Panorama de vulnerabilidad total SBOM:  {panorama_with_sbom:.2f}")
print(f"Tiempo promedio de detección No SBOM:    {avg_detect_no:.1f} días")
print(f"Tiempo promedio de detección SBOM:       {avg_detect_with:.1f} días")
print(f"Tiempo promedio de remediación No SBOM:  {avg_remed_no:.1f} días")
print(f"Tiempo promedio de remediación SBOM:     {avg_remed_with:.1f} días")
print(f"Tiempo total promedio para remediar (No SBOM): {avg_total_no:.1f} días")
print(f"Tiempo total promedio para remediar(SBOM): {avg_total_with:.1f} días")

porcentaje_mejora_vuln = ((panorama_no_sbom - panorama_with_sbom) / panorama_no_sbom) * 100
porcentaje_mejora_deteccion = ((avg_detect_no - avg_detect_with) / avg_detect_no) * 100
porcentaje_mejora_remediacion = ((avg_remed_no - avg_remed_with) / avg_remed_no) * 100
porcentaje_mejora_total_remediar = ((avg_total_no - avg_total_with) / avg_total_no) * 100

print(f"Panorama de vulnerabilidad total: {porcentaje_mejora_vuln:.2f} %")
print(f"Tiempo promedio de detección:       {porcentaje_mejora_deteccion:.1f} %")
print(f"Tiempo promedio de remediación:     {porcentaje_mejora_remediacion:.1f} %")
print(f"Tiempo total promedio para remediar: {porcentaje_mejora_total_remediar:.1f} %")

# Comparación del panorama de vulnerabilidades
plt.figure(figsize=(8, 5))
plt.bar(["No SBOM", "SBOM"], [panorama_no_sbom, panorama_with_sbom], color=["red", "green"])
plt.xlabel("Escenario")
plt.ylabel("Puntuación del panorama de vulnerabilidad")
plt.title("Exposición a la vulnerabilidad: SBOM vs No SBOM")
plt.show()

# Comparación del tiempo de detección
plt.figure(figsize=(8, 5))
plt.bar(["No SBOM", "SBOM"], [avg_detect_no, avg_detect_with], color=["red", "green"])
plt.xlabel("Escenario")
plt.ylabel("Tiempo promedio de detección (Días)")
plt.title("Tiempo promedio de detección de vulnerabilidades: SBOM vs No SBOM")
plt.show()

# Comparación del tiempo de remediación
plt.figure(figsize=(8, 5))
plt.bar(["No SBOM", "SBOM"], [avg_remed_no, avg_remed_with], color=["red", "green"])
plt.xlabel("Escenario")
plt.ylabel("Tiempo promedio de remediación (Días)")
plt.title("Tiempo promedio de remediación de vulnerabilidades: SBOM vs No SBOM")
plt.show()

# Tiempo total desde la divulgación hasta la remediación
plt.figure(figsize=(8, 5))
plt.bar(["No SBOM", "SBOM"], [avg_total_no, avg_total_with], color=["red", "green"])
plt.xlabel("Escenario")
plt.ylabel("Tiempo total para remediar (Días)")
plt.title("Duración total de la vulnerabilidad: SBOM vs No SBOM")
plt.show()