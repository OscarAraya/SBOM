import json
import pyodbc
from datetime import datetime
import os
import glob

def insert_cve_data(conn, cursor, json_file):
    with open(json_file, 'r', encoding='utf-8') as file:
        data = json.load(file)

    for cve_item in data.get("CVE_Items", []):
        cve_id = cve_item["cve"]["CVE_data_meta"]["ID"]
        published_date_str = cve_item.get("publishedDate", "N/A")
        last_modified_date_str = cve_item.get("lastModifiedDate", "N/A")

        # Convert date strings to DATETIME format
        if published_date_str != "N/A":
            published_date = datetime.strptime(published_date_str, "%Y-%m-%dT%H:%MZ")
            published_date = published_date.strftime("%Y-%m-%d %H:%M:%S")
        else:
            published_date = None

        if last_modified_date_str != "N/A":
            last_modified_date = datetime.strptime(last_modified_date_str, "%Y-%m-%dT%H:%MZ")
            last_modified_date = last_modified_date.strftime("%Y-%m-%d %H:%M:%S")
        else:
            last_modified_date = None
        
        # Extract CWE ID (if available)
        cwe_id = "N/A"
        problemtype_data = cve_item["cve"]["problemtype"]["problemtype_data"]
        if problemtype_data and problemtype_data[0].get("description"):
            cwe_id = problemtype_data[0]["description"][0].get("value", "N/A")
        
        # Extract CVSS metrics (CVSSv2, CVSSv3, or CVSSv3.1)
        cvss_version = "N/A"
        vector_string = "N/A"
        base_score = None
        impact_score = None
        exploitability_score = None
        severity = "N/A"
        
        if "impact" in cve_item:
            if "baseMetricV3" in cve_item["impact"]:
                cvss_version = "CVSSv3.1"
                cvss_data = cve_item["impact"]["baseMetricV3"]["cvssV3"]
                vector_string = cvss_data.get("vectorString", "N/A")
                base_score = cvss_data.get("baseScore", None)
                impact_score = cve_item["impact"]["baseMetricV3"].get("impactScore", None)
                exploitability_score = cve_item["impact"]["baseMetricV3"].get("exploitabilityScore", None)
                severity = cvss_data.get("baseSeverity", "N/A")
            elif "baseMetricV2" in cve_item["impact"]:
                cvss_version = "CVSSv2"
                cvss_data = cve_item["impact"]["baseMetricV2"]["cvssV2"]
                vector_string = cvss_data.get("vectorString", "N/A")
                base_score = cvss_data.get("baseScore", None)
                impact_score = cve_item["impact"]["baseMetricV2"].get("impactScore", None)
                exploitability_score = cve_item["impact"]["baseMetricV2"].get("exploitabilityScore", None)
                severity = cve_item["impact"]["baseMetricV2"].get("severity", "N/A")
        
        cursor.execute("""
            INSERT INTO CVE_History (
                cve_id, published_date, last_modified_date, cwe_id, severity,
                cvss_version, vector_string, base_score, impact_score, exploitability_score
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cve_id,
            published_date,
            last_modified_date,
            cwe_id,
            severity,
            cvss_version,
            vector_string,
            base_score,
            impact_score,
            exploitability_score
        ))
        
    conn.commit()

def process_all_nvdcve_files(directory):
    # Connect to the database
    server = 'DESKTOP-3FC1SUJ'
    database = 'SBOM'

    conn = pyodbc.connect(f'DRIVER={{SQL Server}};SERVER={server};DATABASE={database};Trusted_Connection=yes;')
    cursor = conn.cursor()

    # Find all JSON files containing "nvdcve" in their names
    file_pattern = os.path.join(directory, "*nvdcve*.json")
    nvdcve_files = glob.glob(file_pattern)

    # Process each file
    for file_path in nvdcve_files:
        print(f"Processing file: {file_path}")
        try:
            insert_cve_data(conn, cursor, file_path)
        except Exception as e:
            print(f"Error processing file {file_path}: {e}")

    # Close the database connection
    cursor.close()
    conn.close()

# Specify the directory containing the JSON files
directory_path = "."
process_all_nvdcve_files(directory_path)