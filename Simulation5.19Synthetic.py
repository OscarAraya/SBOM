import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime, timedelta

def generate_synthetic_data(
    n_releases=10,
    start_date="2022-01-01",
    days_between_releases=30,
    main_repo="angular/angular",
    artifact_names=None,
    max_vulnerabilities=5,
    seed=42
):
    """
    Generates a synthetic dataset with:
    - 'version': simulated release versions (v2.1.0, v2.2.0, etc.)
    - 'published_at': release dates
    - 'artifact_name': randomly chosen from a set of possible artifacts
    - 'cve_id': a random CVE ID for each vulnerability
    
    :param n_releases: number of releases to simulate
    :param start_date: initial date for the first release
    :param days_between_releases: how many days between each release
    :param main_repo: name of the main repo (not third-party)
    :param artifact_names: list of possible third-party artifacts
    :param max_vulnerabilities: maximum number of vulnerabilities per release/artifact
    :param seed: random seed for reproducibility
    :return: A pandas DataFrame with columns [version, published_at, artifact_name, cve_id]
    """
    np.random.seed(seed)
    
    # Default artifact names if none provided
    if artifact_names is None:
        artifact_names = [
            "requests", "numpy", "pandas", "scipy",
            "matplotlib", "urllib3", "protobuf"
        ]
    
    # Generate synthetic release versions
    # For example: v2.1.0, v2.2.0, v2.3.0...
    releases = [f"v2.{i}.0" for i in range(1, n_releases+1)]
    
    # Generate corresponding published_at dates
    start_dt = datetime.strptime(start_date, "%Y-%m-%d")
    release_dates = [start_dt + timedelta(days=i * days_between_releases) for i in range(n_releases)]
    
    # Prepare list to hold rows of synthetic data
    data_rows = []
    
    # For each release, we'll randomly choose how many third-party artifacts to have
    # and how many vulnerabilities exist for each artifact
    for i, release in enumerate(releases):
        pub_date = release_dates[i]
        
        # Randomly decide how many different artifacts are in this release
        n_artifacts = np.random.randint(1, len(artifact_names)+1)
        chosen_artifacts = np.random.choice(artifact_names, size=n_artifacts, replace=False)
        
        # Always include the main repo artifact to simulate "internal" code
        # We'll handle it separately if we want.
        # For simplicity, let's assume each release definitely has the main repo artifact
        # plus a random selection of third-party artifacts.
        chosen_artifacts = list(chosen_artifacts) + [main_repo]
        
        for artifact in chosen_artifacts:
            # Randomly decide how many vulnerabilities are associated with this artifact
            n_vulns = np.random.randint(0, max_vulnerabilities+1)
            
            # Create that many CVE entries
            for _ in range(n_vulns):
                # Synthesize a random CVE ID
                cve_id = f"CVE-2025-{np.random.randint(1000,9999)}"
                
                data_rows.append({
                    "version": release,
                    "published_at": pub_date.strftime("%Y-%m-%d"),
                    "artifact_name": artifact,
                    "cve_id": cve_id
                })
    
    df_synth = pd.DataFrame(data_rows)
    return df_synth

# Generate synthetic data
df = generate_synthetic_data(
    n_releases=10,
    start_date="2022-01-01",
    days_between_releases=30,
    main_repo="tensorflow/tensorflow",
    artifact_names=["requests", "numpy", "pandas", "scipy", "matplotlib", "urllib3", "protobuf"],
    max_vulnerabilities=5,
    seed=42
)

print("Synthetic dataset preview:\n", df.head(10))

# Convert published_at to datetime
df['release_date'] = pd.to_datetime(df['published_at'], errors='coerce')

# Sort by release_date
df.sort_values('release_date', inplace=True)

# Mark third-party artifacts
main_repo = "tensorflow/tensorflow"
df["is_third_party"] = df["artifact_name"] != main_repo

# Filter only third-party vulnerabilities
third_party_df = df[df["is_third_party"]]

# Group by version to count vulnerabilities (Metric B.31)
vuln_count = third_party_df.groupby(["version"])["cve_id"].count().reset_index(name="vulnerabilities")

# Match each version to its earliest release date
release_dates = df.groupby("version")["release_date"].min().reset_index()
vuln_count = pd.merge(vuln_count, release_dates, on="version", how="left")

# Sort by release_date again
vuln_count.sort_values("release_date", inplace=True)

# If you want a quick look
print("\nVulnerability Count per Release (Third-Party Only):\n", vuln_count)

# Example: 50% reduction factor
reduction_factor = 0.5

vuln_count["vulnerabilities_sbom"] = (
    vuln_count["vulnerabilities"] * reduction_factor
).astype(int)

plt.figure(figsize=(12, 6))

plt.plot(
    vuln_count["release_date"], 
    vuln_count["vulnerabilities"], 
    marker="o", 
    label="Without SBOM"
)

plt.plot(
    vuln_count["release_date"], 
    vuln_count["vulnerabilities_sbom"], 
    marker="o", 
    label="With SBOM"
)

plt.xlabel("Release Date")
plt.ylabel("Number of Third-Party Vulnerabilities (Metric B.31)")
plt.title("Impact of SBOM on Third-Party Vulnerabilities (Synthetic Data)")
plt.legend()
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()
