import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# Load data from CSV file with headers
df = pd.read_csv('Data.csv')

# Calculate the frequency of CVEs per version (tag_name)
cve_counts = df.groupby('tag_name').size().reset_index(name='cve_frequency')

# Merge frequency back to original DataFrame
df = df.merge(cve_counts, on='tag_name')

# Scenario without SBOM: Assume vulnerabilities affect multiple versions (realistic synthetic scenario)
df['Affected_Apps_No_SBOM'] = df['base_score'] * np.random.randint(3, 6, size=len(df))

# Scenario with SBOM: Assume early detection minimizes spread
df['Affected_Apps_With_SBOM'] = df['base_score'] * np.random.randint(1, 3, size=len(df))

# Calculate Vulnerability Panorama scores
panorama_no_sbom = df['Affected_Apps_No_SBOM'].sum()
panorama_sbom = df['Affected_Apps_With_SBOM'].sum()

print(f"Vulnerability Panorama WITHOUT SBOM: {panorama_no_sbom}")
print(f"Vulnerability Panorama WITH SBOM: {panorama_sbom}")

# Visualization
scenarios = ['Without SBOM', 'With SBOM']
scores = [panorama_no_sbom, panorama_sbom]

plt.bar(scenarios, scores, color=['red', 'green'])
plt.title('ISO 27004 B.30 Vulnerability Panorama Comparison')
plt.ylabel('Total Vulnerability Panorama Score')
plt.xlabel('Scenario')
plt.grid(axis='y')
plt.show()