# Not being used atm
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# Load TensorFlow CVE dataset
file_path = "TensorFlowData.csv"
df = pd.read_csv(file_path)

# Convert date to datetime and sort by release order
df['published_at'] = pd.to_datetime(df['published_at'])
df.sort_values('published_at', inplace=True)

# Identify if a release is production or prerelease
df['release_type'] = df['prerelease'].apply(lambda x: 'Prerelease' if x == 1 else 'Production')

# Function to simulate vulnerabilities per release with and without SBOM
def simulate_vulnerabilities(dataframe):
    non_sbom_counts = []
    sbom_counts = []
    seen_vulns = set()  # Track known vulnerabilities

    for release, group in dataframe.groupby('tag_name', sort=False):
        vulns = set(group['cve_id'])
        non_sbom_counts.append(len(vulns))  # All vulnerabilities found in this release

        # SBOM scenario: consider only new, previously unseen vulnerabilities
        new_vulns = vulns - seen_vulns
        sbom_counts.append(len(new_vulns))

        seen_vulns.update(new_vulns)  # Update known vulnerabilities list

    return non_sbom_counts, sbom_counts

# Apply simulation to production releases
prod_df = df[df['release_type'] == 'Production']
non_sbom, sbom = simulate_vulnerabilities(prod_df)

# Calculate percentage reduction in vulnerabilities due to SBOM
vuln_reduction_pct = (sum(non_sbom) - sum(sbom)) / sum(non_sbom) * 100

# Simulate MTTR (Mean Time to Remediate) for vulnerabilities
np.random.seed(42)
mttr_no_sbom = np.random.normal(loc=53.5, scale=10, size=len(prod_df))  # Without SBOM
mttr_sbom = mttr_no_sbom * 0.9  # Assume SBOM improves MTTR by ~10%

# Calculate improvement in MTTR
mttr_reduction = ((mttr_no_sbom.mean() - mttr_sbom.mean()) / mttr_no_sbom.mean()) * 100

# Visualization: Vulnerability exposure over releases
plt.figure(figsize=(10, 5))
plt.plot(non_sbom, label="Without SBOM (All Found Vulns)", color='red', linestyle='dashed')
plt.plot(sbom, label="With SBOM (New Unique Vulns)", color='blue', linewidth=2)
plt.xlabel("Release Index")
plt.ylabel("Number of Vulnerabilities")
plt.title("Vulnerability Exposure per Release: SBOM vs Non-SBOM")
plt.legend()
plt.grid(True)
plt.show()

# Visualization: MTTR improvement with SBOM
plt.figure(figsize=(10, 5))
sns.histplot(mttr_no_sbom, color="red", kde=True, label="Without SBOM", bins=30)
sns.histplot(mttr_sbom, color="blue", kde=True, label="With SBOM", bins=30)
plt.xlabel("MTTR (Days)")
plt.ylabel("Frequency")
plt.title("Mean Time to Remediate (MTTR) Distribution: SBOM vs Non-SBOM")
plt.legend()
plt.show()

# Display summary of improvements
results_summary = pd.DataFrame({
    "Metric": ["Vulnerability Reduction (%)", "MTTR Reduction (%)"],
    "Improvement": [vuln_reduction_pct, mttr_reduction]
})

#import ace_tools as tools
#tools.display_dataframe_to_user(name="SBOM Impact Summary", dataframe=results_summary)
