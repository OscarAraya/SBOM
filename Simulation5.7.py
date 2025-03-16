import pandas as pd
import numpy as np

# Load the real vulnerability dataset (TensorFlowData.csv)
df = pd.read_csv("TensorFlowData.csv")
df["base_score"] = pd.to_numeric(df["base_score"], errors="coerce")

# Bin CVSS base scores into severity categories (Low, Medium, High)
bins = [0, 4, 7, 10]
labels = ["Low", "Medium", "High"]
df["Severity"] = pd.cut(df["base_score"], bins=bins, labels=labels, include_lowest=True)

# Define incident probability for each severity WITHOUT SBOM (base rates)
prob_no_sbom = {"Low": 0.10, "Medium": 0.40, "High": 0.80}
# Define reduced incident probability for each severity WITH SBOM (improved rates)
prob_with_sbom = {"Low": 0.05, "Medium": 0.25, "High": 0.60}

# Function to simulate security incidents for each vulnerability based on probabilities
def simulate_incidents(dataframe, prob_mapping, seed=None):
    if seed is not None:
        np.random.seed(seed)
    df_sim = dataframe.copy()
    incidents = []
    for sev in df_sim["Severity"]:
        p = prob_mapping.get(sev, 0)
        incidents.append(1 if np.random.rand() < p else 0)
    df_sim["Incident"] = incidents
    return df_sim

# Simulate incidents for both scenarios
df_no_sbom  = simulate_incidents(df, prob_no_sbom, seed=42)
df_with_sbom = simulate_incidents(df, prob_with_sbom, seed=42)

# Assign remediation (recovery) time for each incident (in days)
# Baseline mean times (in days) for incident resolution without vs. with SBOM
mean_time_no_sbom  = {"Low": 15, "Medium": 10, "High": 5}   # e.g., days to resolve without SBOM
mean_time_with_sbom = {"Low": 10, "Medium": 7, "High": 3}   # e.g., faster resolution with SBOM

# Apply remediation times with some variance (±20% of mean time)
np.random.seed(42)
rem_time_no, rem_time_with = [], []
for sev, incident in zip(df_no_sbom["Severity"], df_no_sbom["Incident"]):
    if incident == 1:
        base = mean_time_no_sbom.get(sev, 10)
        # random variation of up to ±20%
        rem_time_no.append(base * (1 + (np.random.rand() - 0.5) * 0.4))
    else:
        rem_time_no.append(np.nan)
for sev, incident in zip(df_with_sbom["Severity"], df_with_sbom["Incident"]):
    if incident == 1:
        base = mean_time_with_sbom.get(sev, 7)
        rem_time_with.append(base * (1 + (np.random.rand() - 0.5) * 0.4))
    else:
        rem_time_with.append(np.nan)
df_no_sbom["RemediationTime"]  = rem_time_no
df_with_sbom["RemediationTime"] = rem_time_with

# Calculate key metrics:
total_incidents_no_sbom  = df_no_sbom["Incident"].sum()
total_incidents_with_sbom = df_with_sbom["Incident"].sum()
MTTR_no_sbom  = df_no_sbom[df_no_sbom["Incident"] == 1]["RemediationTime"].mean()
MTTR_with_sbom = df_with_sbom[df_with_sbom["Incident"] == 1]["RemediationTime"].mean()

# Define threshold for "learning from incidents" (e.g., 80% of incidents yield improvements)
learning_threshold = 0.80
# Assume X% of incidents trigger improvement actions (could be derived from data or set by policy)
# For demonstration, assume 70% without SBOM vs 90% with SBOM lead to improvements (lessons learned)
learn_fraction_no_sbom  = 0.70
learn_fraction_with_sbom = 0.90

# Compute whether the learning metric meets the threshold in each scenario
metric_no_sbom  = learn_fraction_no_sbom 
metric_with_sbom = learn_fraction_with_sbom
meets_threshold_no = metric_no_sbom  >= learning_threshold
meets_threshold_with = metric_with_sbom >= learning_threshold

# Output simulation results
print(f"Total vulnerabilities analyzed: {len(df)}")
print(f"Total Incidents (No SBOM): {total_incidents_no_sbom}")
print(f"Total Incidents (With SBOM): {total_incidents_with_sbom}")
print(f"Incident Reduction with SBOM: {((total_incidents_no_sbom - total_incidents_with_sbom) / total_incidents_no_sbom) * 100:.1f}%")
print(f"Mean Time to Recovery (No SBOM): {MTTR_no_sbom:.2f} days")
print(f"Mean Time to Recovery (With SBOM): {MTTR_with_sbom:.2f} days")
print(f"MTTR Improvement with SBOM: {((MTTR_no_sbom - MTTR_with_sbom) / MTTR_no_sbom) * 100:.1f}% faster")
print(f"Learning from Incidents (No SBOM): {learn_fraction_no_sbom * 100:.0f}% of incidents -> improvements "
      f"{'(met threshold)' if meets_threshold_no else '(below threshold)'}")
print(f"Learning from Incidents (With SBOM): {learn_fraction_with_sbom * 100:.0f}% of incidents -> improvements "
      f"{'(met threshold)' if meets_threshold_with else '(below threshold)'}")

# --- Synthetic Data Generation for additional repositories ---
def generate_synthetic_vulns(repo_name, count, severity_dist=None):
    """Generate synthetic vulnerability dataset for a given repo."""
    if severity_dist is None:
        # Use severity distribution from real data if not provided
        severity_dist = df["Severity"].value_counts(normalize=True).to_dict()
    # Sample severities for synthetic vulnerabilities
    severities = np.random.choice(list(severity_dist.keys()), size=count, p=list(severity_dist.values()))
    # Assign random base scores in the appropriate range for each severity
    base_scores = []
    for sev in severities:
        if sev == "Low":
            score = np.random.uniform(0, 4)   # low severity CVSS range
        elif sev == "Medium":
            score = np.random.uniform(4, 7)   # medium severity CVSS range
        else:
            score = np.random.uniform(7, 10)  # high (including critical) CVSS range
        base_scores.append(round(score, 1))
    # Randomly assign each vuln to one of a few release versions
    releases = [f"v{major}.{minor}" for major in range(1, 3) for minor in range(0, 5)]  # e.g., v1.0 ... v2.4
    tags = np.random.choice(releases, size=count)
    # Create DataFrame
    data = pd.DataFrame({
        "repo": repo_name,
        "tag_name": tags,
        "base_score": base_scores
    })
    data["Severity"] = pd.cut(data["base_score"], bins=bins, labels=labels, include_lowest=True)
    return data

# Generate synthetic datasets for additional repositories
repoA = generate_synthetic_vulns("RepoA", count=300)
repoB = generate_synthetic_vulns("RepoB", count=600)
repoC = generate_synthetic_vulns("RepoC", count=200)

# Function to run simulation and gather metrics for a given dataset
def evaluate_repo(dataframe):
    df_ns = simulate_incidents(dataframe, prob_no_sbom)      # no SBOM
    df_s  = simulate_incidents(dataframe, prob_with_sbom)    # with SBOM
    # Assign remediation times for incidents
    rem_ns = []; rem_s = []
    for sev, inc in zip(df_ns["Severity"], df_ns["Incident"]):
        rem_ns.append(np.nan if inc == 0 else mean_time_no_sbom.get(sev, 10) * (1 + (np.random.rand()-0.5)*0.4))
    for sev, inc in zip(df_s["Severity"], df_s["Incident"]):
        rem_s.append(np.nan if inc == 0 else mean_time_with_sbom.get(sev, 7) * (1 + (np.random.rand()-0.5)*0.4))
    df_ns["RemTime"] = rem_ns
    df_s["RemTime"]  = rem_s
    # Calculate metrics
    incidents_ns = df_ns["Incident"].sum()
    incidents_s  = df_s["Incident"].sum()
    mttr_ns = df_ns[df_ns["Incident"]==1]["RemTime"].mean()
    mttr_s  = df_s[df_s["Incident"]==1]["RemTime"].mean()
    learn_metric_ns = 0.70  # assume 70% for no-SBOM
    learn_metric_s  = 0.90  # assume 90% for SBOM
    meets_ns = learn_metric_ns >= learning_threshold
    meets_s  = learn_metric_s  >= learning_threshold
    return {
        "count": len(dataframe),
        "inc_no": incidents_ns, "inc_s": incidents_s,
        "mttr_no": mttr_ns, "mttr_s": mttr_s,
        "learn_no_pct": learn_metric_ns * 100, "learn_s_pct": learn_metric_s * 100,
        "learn_no_ok": meets_ns, "learn_s_ok": meets_s
    }

# Evaluate all datasets (real and synthetic)
datasets = {"GitHubRepo": df} #, "RepoA": repoA, "RepoB": repoB, "RepoC": repoC
for name, data in datasets.items():
    np.random.seed(1)  # reset RNG for fairness per repo
    metrics = evaluate_repo(data)
    print(f"\n[{name}] Vulnerabilities: {metrics['count']}")
    print(f"Incidents (No SBOM vs SBOM): {metrics['inc_no']} vs {metrics['inc_s']}  "
          f"Reduction: {((metrics['inc_no'] - metrics['inc_s'])/metrics['inc_no']*100):.1f}%")
    print(f"MTTR (No SBOM vs SBOM): {metrics['mttr_no']:.2f} vs {metrics['mttr_s']:.2f} days  "
          f"Improvement: {((metrics['mttr_no']-metrics['mttr_s'])/metrics['mttr_no']*100):.1f}%")
    print(f"Learning Metric (No SBOM vs SBOM): {metrics['learn_no_pct']:.0f}%{'*' if metrics['learn_no_ok'] else ''} vs "
          f"{metrics['learn_s_pct']:.0f}%{'*' if metrics['learn_s_ok'] else ''}  "
          f"Threshold {learning_threshold*100:.0f}%{'*' if metrics['learn_s_ok'] or metrics['learn_no_ok'] else ''}")
