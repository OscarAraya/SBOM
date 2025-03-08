import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.dates import DateFormatter

def visualize_deployments(deployments, affected):
    # Prepare Data
    deployment_dates = [d["deployed_at"] for d in deployments]
    affected_dates = [a["deployment"]["deployed_at"] for a in affected]

    df = pd.DataFrame({
        "deployment_date": deployment_dates,
        "affected": [date in affected_dates for date in deployment_dates]
    })

    # Timeline Plot
    fig, ax = plt.subplots(figsize=(14, 6))
    ax.scatter(df["deployment_date"], [1] * len(df), 
               c=df["affected"].map({True: "red", False: "green"}),
               label="Deployments", s=100, marker="o")

    ax.set_title("Deployment Timeline with Vulnerabilities")
    ax.set_xlabel("Date")
    ax.set_yticks([])
    ax.xaxis.set_major_formatter(DateFormatter("%Y-%m-%d"))
    ax.legend(["Unaffected", "Affected"], loc="upper left")
    plt.grid()
    plt.show()

    # Severity Bar Chart
    severities = [a["severity"] for a in affected]
    if severities:
        pd.Series(severities).value_counts().plot(kind="bar", color="orange", figsize=(10, 5))
        plt.title("Affected Deployments by Severity")
        plt.xlabel("Severity")
        plt.ylabel("Count")
        plt.show()
    else:
        print("No affected deployments to show severity distribution.")

# Call the visualization
visualize_deployments(deployments, affected)