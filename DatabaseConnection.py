import pyodbc
import pandas as pd
import json
import os

def commit_merge_insert(conn, cursor):
    # json_file = 'repo_merge_data.json'
    json_file = 'repo_commit_data.json'
    with open(json_file, 'r', encoding='utf-8') as file:
        data = json.load(file)

    repo_data = list(data.values())[0]

    #df = pd.DataFrame(repo_data.items(), columns=['merge_date', 'merge_count'])
    df = pd.DataFrame(repo_data.items(), columns=['commit_date', 'commit_count'])

    #insert_query = f"INSERT INTO {table_name} (repo_id, merge_date, merge_count) VALUES (1, ?, ?)"
    insert_query = f"INSERT INTO {table_name} (repo_id, commit_date, commit_count) VALUES (1, ?, ?)"

    for row in df.itertuples(index=False, name=None):
        cursor.execute(insert_query, row)

    conn.commit()

def security_advisories_insert(conn, cursor):

    json_file = 'security_advisories.json'
    with open(json_file, 'r', encoding='utf-8') as file:
        data = json.load(file)


    for repo_name, advisories in data.items():
        for advisory in advisories:

            insert_advisory_query = """
                INSERT INTO SecurityAdvisories (repo_id, repository_name, ghsa_id, cve_id, html_url, published_at, summary, severity, updated_at)
                OUTPUT INSERTED.advisory_id
                VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            cursor.execute(insert_advisory_query, (
                repo_name,
                advisory['ghsa_id'],
                advisory.get('cve_id', None),
                advisory['html_url'],
                advisory['published_at'],
                advisory['summary'],
                advisory['severity'],
                advisory['updated_at']
            ))
            advisory_id = cursor.fetchone()[0]

            for vuln in advisory.get('vulnerabilities', []):
                cursor.execute("""
                    INSERT INTO VulnerablePackages (advisory_id, package_name, vulnerable_version_range)
                    VALUES (?, ?, ?)
                """, (advisory_id, vuln['package'], vuln['vulnerable_version_range']))

            for version in [3, 4]:
                cvss_key = f'cvss_{version}'
                if advisory.get(cvss_key):
                    cursor.execute("""
                        INSERT INTO CVSS_Scores (advisory_id, version, vector_string, score)
                        VALUES (?, ?, ?, ?)
                    """, (advisory_id, version, advisory[cvss_key]['vector_string'], advisory[cvss_key]['score']))

    conn.commit()

    print("Data successfully inserted into SQL Server.")

def insert_cve_mapping(conn, cursor, tag_name, json_file):
    with open(json_file, 'r', encoding='utf-8') as file:
        data = json.load(file)

    for cve_id in data:
        cursor.execute("""
            INSERT INTO CVE_Mapping (repo_id, tag_name, cve_id)
            VALUES (1, ?, ?)
        """, (
            tag_name,
            cve_id
        ))
        
    conn.commit()

def insert_repo_releases(conn, cursor, json_file):
    with open(json_file, 'r') as file:
        data = json.load(file)

    for release in data:
        cursor.execute("""
            INSERT INTO Repo_Releases (repo_id, tag_name, tarball_url, prerelease, published_at)
            VALUES (1, ?, ?, ?, ?)
        """, (
            release["tag_name"],
            release["tarball_url"],
            1 if release["prerelease"] else 0,
            release["published_at"]
        ))

    conn.commit()

def process_cve_files(directory, conn, cursor):
    for filename in os.listdir(directory):
        if "cve_analysis.json" in filename:
            print(f"Processing: {filename}")
            insert_cve_mapping(conn, cursor, filename.replace(".cve_analysis.json", ""), os.path.join(directory, filename))

if __name__ == "__main__":
    server = 'DESKTOP-3FC1SUJ'
    database = 'SBOM'
    #table_name = 'Merges'
    table_name = 'Commits'

    #conn = pyodbc.connect(f'DRIVER={{SQL Server}};SERVER={server};DATABASE={database};UID={username};PWD={password}')
    conn = pyodbc.connect(f'DRIVER={{SQL Server}};SERVER={server};DATABASE={database};Trusted_Connection=yes;')
    cursor = conn.cursor()

    #commit_merge_insert(conn, cursor)
    
    #https://docs.github.com/en/rest/commits/commits?apiVersion=2022-11-28
    #https://docs.github.com/en/rest/security-advisories/repository-advisories?apiVersion=2022-11-28#list-repository-security-advisories
    #security_advisories_insert(conn, cursor)

    insert_repo_releases(conn, cursor, "repo_releases.json")
    process_cve_files(".", conn, cursor)

    cursor.close()
    conn.close()
    