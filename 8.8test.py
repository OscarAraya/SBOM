import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import matplotlib.pyplot as plt

# Load your data
df = pd.read_csv('tensorflow.csv')

# Convert to datetime
df['published_at'] = pd.to_datetime(df['published_at'])

# Simulate discovery date (assuming vulnerabilities are discovered after release)
# In reality, this would come from your security scanning tools
df['discovery_date'] = df['published_at'] + pd.to_timedelta(
    np.random.randint(30, 180, size=len(df)), unit='d'
)

# Simulate remediation time based on risk level and SBOM availability
def simulate_remediation_time(risk_level, has_sbom=False):
    # Base remediation times (in days) by risk level
    base_times = {
        'Crítico': 30,
        'Alto': 45,
        'Medio': 60,
        'Bajo': 90
    }
    
    # SBOM reduces remediation time
    sbom_factor = 0.6 if has_sbom else 1.0  # 40% reduction with SBOM
    
    # Add some randomness
    randomness = np.random.uniform(0.8, 1.2)
    
    return base_times[risk_level] * sbom_factor * randomness

# Apply the function
df['remediation_days_no_sbom'] = df['Risk_Level'].apply(
    lambda x: simulate_remediation_time(x, has_sbom=False)
)
df['remediation_days_with_sbom'] = df['Risk_Level'].apply(
    lambda x: simulate_remediation_time(x, has_sbom=True)
)

# Calculate remediation dates
df['remediation_date_no_sbom'] = df['discovery_date'] + pd.to_timedelta(
    df['remediation_days_no_sbom'], unit='d'
)
df['remediation_date_with_sbom'] = df['discovery_date'] + pd.to_timedelta(
    df['remediation_days_with_sbom'], unit='d'
)

# Calculate MTTR for both scenarios
mttr_no_sbom = df['remediation_days_no_sbom'].mean()
mttr_with_sbom = df['remediation_days_with_sbom'].mean()

print(f"MTTR without SBOM: {mttr_no_sbom:.2f} days")
print(f"MTTR with SBOM: {mttr_with_sbom:.2f} days")
print(f"Improvement: {(1 - mttr_with_sbom/mttr_no_sbom)*100:.2f}% faster remediation with SBOM")
