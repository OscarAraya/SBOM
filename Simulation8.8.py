import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# Set seed for reproducibility
np.random.seed(42)

# Load data
df = pd.read_csv('TensorFlowData.csv')
# Count CVEs per version (how many CVEs each software release has)
cve_counts = df.groupby('tag_name').size().reset_index(name='cve_count')
df = df.merge(cve_counts, on='tag_name')

# Define affected systems (impact scope) for each vulnerability
def affected_systems_no_sbom(cvss_score, cve_count):
    # Base number of affected systems grows with severity (critical > high > low)
    if cvss_score >= 9.0:
        base = np.random.randint(4, 6)    # Critical: 4–5 systems affected
    elif cvss_score >= 7.0:
        base = np.random.randint(3, 5)    # High: 3–4 systems
    else:
        base = np.random.randint(1, 4)    # Low/Med: 1–3 systems
    # If the software version has many CVEs, it might be widely used/outdated – add impact
    extra = cve_count // 5               # e.g. +1 system for each 5 CVEs in that version
    return base + extra

def affected_systems_with_sbom(cvss_score, cve_count):
    # SBOM in use – expected fewer systems impacted due to proactive management
    if cvss_score >= 9.0:
        base = np.random.randint(2, 4)   # Critical: 2–3 systems (faster detection limits spread)
    elif cvss_score >= 7.0:
        base = np.random.randint(1, 3)   # High: 1–2 systems
    else:
        base = 1                         # Low/Med: likely 1 system (minimal impact)
    # Assume SBOM-driven practices avoid large deployments of highly vulnerable versions
    extra = 0  # We minimize extra spread in SBOM scenario
    return base + extra

# Apply the functions to get number of affected systems per CVE in each scenario
df['Affected_Systems_No_SBOM'] = df.apply(lambda x: affected_systems_no_sbom(x['base_score'], x['cve_count']), axis=1)
df['Affected_Systems_With_SBOM'] = df.apply(lambda x: affected_systems_with_sbom(x['base_score'], x['cve_count']), axis=1)

# Calculate vulnerability panorama (severity * affected systems) for each CVE and scenario
df['Vuln_Risk_No_SBOM'] = df['base_score'] * df['Affected_Systems_No_SBOM']
df['Vuln_Risk_With_SBOM'] = df['base_score'] * df['Affected_Systems_With_SBOM']

# Sum up the vulnerability panorama metric for each scenario
panorama_no_sbom = df['Vuln_Risk_No_SBOM'].sum()
panorama_with_sbom = df['Vuln_Risk_With_SBOM'].sum()

# Simulate detection time (days from CVE disclosure to when the organization detects/learns of it)
def detection_time_no_sbom(cvss_score):
    if cvss_score >= 9.0:
        return np.random.randint(1, 16)   # Critical: 1–15 days (likely heard quickly via alerts)
    elif cvss_score >= 7.0:
        return np.random.randint(7, 31)   # High: up to ~30 days (found in routine scanning/news)
    else:
        return np.random.randint(30, 91)  # Low: 1–3 months (might go unnoticed for a while)

def detection_time_with_sbom(cvss_score):
    return np.random.randint(1, 6)        # With SBOM: 1–5 days (very quick automated detection)

df['Detection_Time_No_SBOM'] = df['base_score'].apply(detection_time_no_sbom)
df['Detection_Time_With_SBOM'] = df['base_score'].apply(detection_time_with_sbom)

# Simulate remediation time (days from detection to deploying the fix)
def remediation_time_no_sbom(cvss_score):
    if cvss_score >= 9.0:
        return np.random.randint(30, 91)   # Critical: 1–3 months to remediate
    elif cvss_score >= 7.0:
        return np.random.randint(60, 181)  # High: 2–6 months
    else:
        return np.random.randint(180, 366) # Low/Med: 6–12 months (often delayed)

def remediation_time_with_sbom(cvss_score):
    if cvss_score >= 9.0:
        return np.random.randint(7, 31)    # Critical: ~1–4 weeks (faster turnaround)
    elif cvss_score >= 7.0:
        return np.random.randint(30, 91)   # High: 1–3 months
    else:
        return np.random.randint(90, 181)  # Low/Med: 3–6 months (still faster than no SBOM)

df['Remediation_Time_No_SBOM'] = df['base_score'].apply(remediation_time_no_sbom)
df['Remediation_Time_With_SBOM'] = df['base_score'].apply(remediation_time_with_sbom)

# Total time from CVE disclosure to remediation (detection + fix time)
df['Total_Time_No_SBOM'] = df['Detection_Time_No_SBOM'] + df['Remediation_Time_No_SBOM']
df['Total_Time_With_SBOM'] = df['Detection_Time_With_SBOM'] + df['Remediation_Time_With_SBOM']

# Calculate average times for summary
avg_detect_no = df['Detection_Time_No_SBOM'].mean()
avg_detect_with = df['Detection_Time_With_SBOM'].mean()
avg_remed_no = df['Remediation_Time_No_SBOM'].mean()
avg_remed_with = df['Remediation_Time_With_SBOM'].mean()
avg_total_no = df['Total_Time_No_SBOM'].mean()
avg_total_with = df['Total_Time_With_SBOM'].mean()

# Print out the simulation results
print(f"Total Vulnerability Panorama WITHOUT SBOM: {panorama_no_sbom:.2f}")
print(f"Total Vulnerability Panorama WITH SBOM:  {panorama_with_sbom:.2f}")
print(f"Average Detection Time WITHOUT SBOM:    {avg_detect_no:.1f} days")
print(f"Average Detection Time WITH SBOM:       {avg_detect_with:.1f} days")
print(f"Average Remediation Time WITHOUT SBOM:  {avg_remed_no:.1f} days")
print(f"Average Remediation Time WITH SBOM:     {avg_remed_with:.1f} days")
print(f"Average Total Time to Remediate (No SBOM): {avg_total_no:.1f} days")
print(f"Average Total Time to Remediate (With SBOM): {avg_total_with:.1f} days")

# Create bar charts comparing SBOM vs. No-SBOM scenarios

# Vulnerability Panorama Comparison
plt.figure(figsize=(8, 5))
plt.bar(["Without SBOM", "With SBOM"], [panorama_no_sbom, panorama_with_sbom], alpha=0.7)
plt.xlabel("Scenario")
plt.ylabel("Vulnerability Panorama Score")
plt.title("Vulnerability Exposure: SBOM vs No SBOM")
plt.grid(axis="y", linestyle="--", alpha=0.5)
plt.show()

# Detection Time Comparison
plt.figure(figsize=(8, 5))
plt.bar(["Without SBOM", "With SBOM"], [avg_detect_no, avg_detect_with], color=["red", "green"], alpha=0.7)
plt.xlabel("Scenario")
plt.ylabel("Average Detection Time (Days)")
plt.title("Average Vulnerability Detection Time: SBOM vs No SBOM")
plt.grid(axis="y", linestyle="--", alpha=0.5)
plt.show()

# Remediation Time Comparison
plt.figure(figsize=(8, 5))
plt.bar(["Without SBOM", "With SBOM"], [avg_remed_no, avg_remed_with], color=["red", "green"], alpha=0.7)
plt.xlabel("Scenario")
plt.ylabel("Average Remediation Time (Days)")
plt.title("Average Vulnerability Remediation Time: SBOM vs No SBOM")
plt.grid(axis="y", linestyle="--", alpha=0.5)
plt.show()

# Total Time from Disclosure to Remediation
plt.figure(figsize=(8, 5))
plt.bar(["Without SBOM", "With SBOM"], [avg_total_no, avg_total_with], color=["red", "green"], alpha=0.7)
plt.xlabel("Scenario")
plt.ylabel("Total Time to Remediate (Days)")
plt.title("Total Vulnerability Lifetime: SBOM vs No SBOM")
plt.grid(axis="y", linestyle="--", alpha=0.5)
plt.show()