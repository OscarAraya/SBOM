import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# 1. Load your CSV dataset
df = pd.read_csv("Data.csv")

# 2. Convert the published_at column into a proper datetime object
df['release_date'] = pd.to_datetime(df['published_at'], errors='coerce')

# 3. Sort the DataFrame by release_date (chronological order)
df.sort_values('release_date', inplace=True)

# 4. Identify third-party artifacts (assume main_repo is "nodejs/node")
main_repo = "tensorflow/tensorflow"
df["is_third_party"] = ~df["artifact_name"].apply(lambda x: str(x) in main_repo)

# If the release information is stored under 'tag_name', rename it to 'version'
if "tag_name" in df.columns:
    df.rename(columns={"tag_name": "version"}, inplace=True)
else:
    raise ValueError("Release/version column not found. Please check your CSV.")

# 5. Filter the DataFrame to include only third-party vulnerabilities
third_party_df = df[df["is_third_party"]]

# 6. Group by version to count vulnerabilities (Metric B.31)
vuln_count = third_party_df.groupby("version")["cve_id"].count().reset_index(name="vulnerabilities")

# 7. Match each version to its earliest release_date
release_dates = df.groupby("version")["release_date"].min().reset_index()
vuln_count = pd.merge(vuln_count, release_dates, on="version", how="left")

# 8. Sort again by release_date
vuln_count.sort_values("release_date", inplace=True)

# 9. Simulate three SBOM scenarios with different reduction levels
np.random.seed(42)  # Ensuring reproducibility

# Basic adoption: 10-30% reduction
vuln_count["reduction_factor_basic"] = np.random.uniform(0.1, 0.3, size=len(vuln_count))
vuln_count["vulnerabilities_sbom_basic"] = (vuln_count["vulnerabilities"] * (1 - vuln_count["reduction_factor_basic"])).astype(int)

# Mature adoption: 30-50% reduction
vuln_count["reduction_factor_mature"] = np.random.uniform(0.3, 0.5, size=len(vuln_count))
vuln_count["vulnerabilities_sbom_mature"] = (vuln_count["vulnerabilities"] * (1 - vuln_count["reduction_factor_mature"])).astype(int)

# Advanced adoption: 50-70% reduction
vuln_count["reduction_factor_advanced"] = np.random.uniform(0.5, 0.7, size=len(vuln_count))
vuln_count["vulnerabilities_sbom_advanced"] = (vuln_count["vulnerabilities"] * (1 - vuln_count["reduction_factor_advanced"])).astype(int)

# 10. Plot the comparison over time
plt.figure(figsize=(12, 6))
plt.plot(
    vuln_count["release_date"],
    vuln_count["vulnerabilities"],
    marker="o",
    color="red",
    linestyle="-",
    label="NO SBOM"
)

plt.plot(
    vuln_count["release_date"],
    vuln_count["vulnerabilities_sbom_basic"],
    marker="o",
    color="blue",
    linestyle=":",
    label="SBOM (Básico)"
)

plt.plot(
    vuln_count["release_date"],
    vuln_count["vulnerabilities_sbom_mature"],
    marker="o",
    color="green",
    linestyle=":",
    label="SBOM (Maduro)"
)

plt.plot(
    vuln_count["release_date"],
    vuln_count["vulnerabilities_sbom_advanced"],
    marker="o",
    color="purple",
    linestyle=":",
    label="SBOM (Avanzado)"
)

plt.xlabel("Fecha Liberación ")  # Release Date
plt.ylabel("Número de vulnerabilidades de terceros")  # Number of Third-Party Vulnerabilities (Metric B.31)
plt.title("Impacto del uso de SBOM en vulnerabilidades de terceros")  # Impact of SBOM on Third-Party Vulnerabilities
plt.legend()
plt.grid(True, linestyle='--', alpha=0.6)
plt.tight_layout()
plt.show()


"""
Se utilizan distintos valores debido al nivel de adopcion y esto depende mucho de las herramientas que se esten utilizando.

https://nios.montana.edu/cyber/products/Impacts%20of%20Software%20Bill%20of%20Materials%20-%20SBOM%20-%20Generation%20on%20Vulnerability%20Detection%20Final%20Version.pdf
https://www.mckinsey.com/capabilities/risk-and-resilience/our-insights/cybersecurity/software-bill-of-materials-managing-software-cybersecurity-risks
https://www.ox.security/sbom-tools-mitigating-supply-chain-risk-driving-compliance/

Basic SBOM Adoption: 10-30% reduction (Blue)
Mature SBOM Adoption: 30-50% reduction (Green)
Advanced SBOM Adoption: 50-70% reduction (Purple)
"""