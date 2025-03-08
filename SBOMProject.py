import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import json

np.random.seed(42)
"""
# Example GitHub data (deployments)
github_data = [{"repo": "example-repo", "commits": 50, "workflows": 20}]
df_github = pd.DataFrame(github_data)

# Example GitLab data (pipelines)
gitlab_data = [{"project": "example-project", "pipelines": 30, "vulnerabilities": 5}]
df_gitlab = pd.DataFrame(gitlab_data)

# Merge both
df = pd.concat([df_github, df_gitlab], ignore_index=True)
print(df)
"""

"""
sns.barplot(x="repo", y="commits", data=df_github)
plt.title("Commits per Repository (GitHub)")
plt.show()

sns.barplot(x="project", y="vulnerabilities", data=df_gitlab)
plt.title("Vulnerabilities per GitLab Project")
plt.show()
"""

# Define environments
environments = ["DEV", "UAT", "PROD"]

# Generate synthetic deployment frequencies
data = {
    "Environment": np.random.choice(environments, 1000),
    "Deployments_per_day": np.random.poisson(lam=5, size=1000),  # Avg 5 deployments per day
    "Vulnerabilities_found": np.random.poisson(lam=3, size=1000),  # Avg 3 vulnerabilities per deployment
}

df = pd.DataFrame(data)

# Assign risk levels
df["Risk_Level"] = pd.cut(df["Vulnerabilities_found"], bins=[-1,1,3,10], labels=["Low", "Medium", "High"])

print(df.head())

df["SBOM_Used"] = np.random.choice([True, False], size=1000)
df["Time_to_fix"] = np.where(df["SBOM_Used"], np.random.uniform(1, 5, size=1000), np.random.uniform(5, 20, size=1000))

sns.boxplot(x="Environment", y="Time_to_fix", hue="SBOM_Used", data=df)
plt.title("Time to Fix Vulnerabilities with vs Without SBOM")
plt.show()

#2️⃣ Analyzing SBOM vs. Non-SBOM Deployments
# Load GitHub and GitLab data
with open("github_data.json") as f:
    github_data = json.load(f)

with open("gitlab_data.json") as f:
    gitlab_data = json.load(f)

# Create DataFrame
df = pd.DataFrame([
    {"Platform": "GitHub", "Deployments": github_data["workflows"], "Vulnerabilities": np.random.randint(1, 10)},
    {"Platform": "GitLab", "Deployments": gitlab_data["pipelines"], "Vulnerabilities": gitlab_data["vulnerabilities"]}
])

# Add SBOM impact simulation (reduces vulnerabilities)
df["SBOM_Used"] = np.random.choice([True, False], size=len(df))
df["Reduced_Vulnerabilities"] = df.apply(lambda x: x["Vulnerabilities"] * 0.5 if x["SBOM_Used"] else x["Vulnerabilities"], axis=1)

print(df)

#3️⃣ Plot and Compare SBOM vs. Non-SBOM Deployments
sns.barplot(x="Platform", y="Reduced_Vulnerabilities", hue="SBOM_Used", data=df)
plt.title("Impact of SBOM on Reducing Vulnerabilities")
plt.show()
