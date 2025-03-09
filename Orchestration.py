import requests
import os
import subprocess
import json
import time

github_api_url = "https://api.github.com"
nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
headers = {
    "Accept": "application/vnd.github+json",
    "Authorization": "Bearer "
}

nvd_headers = {
    "key": "",
    "User-Agent": "MySecurityTool/1.0"
}

def get_recent_releases(repo_full_name, per_page=25):
    url = f"{github_api_url}/repos/{repo_full_name}/releases?per_page={per_page}"
    response = requests.get(url, headers=headers)
    
    if response.status_code != 200:
        print(f"Error fetching releases: {response.status_code}, {response.text}")
        return []
    
    releases = [
        {
            "tag_name": release["tag_name"],
            "tarball_url": release["tarball_url"],
            "prerelease": release["prerelease"],
            "published_at": release.get("published_at", "N/A")
        }
        for release in response.json()
    ]
    
    with open("repo_releases.json", "w") as f:
        json.dump(releases, f, indent=4)
    
    print("Release data saved to repo_releases.json")
    return releases

def download_tarball(tarball_url, save_path):
    response = requests.get(tarball_url, headers=headers, stream=True)
    if response.status_code == 200:
        with open(save_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f"Downloaded {save_path}")
        return True
    else:
        print(f"Failed to download tarball: {response.status_code}, {response.text}")
        return False

def extract_tarball(tar_path, extract_to):
    os.system(f"mkdir {extract_to} & tar -xvzf {tar_path} -C {extract_to}") # --strip-components=1
    print(f"Extracted {tar_path} to {extract_to}")

def generate_sbom(directory, output_file):
    # https://github.com/anchore/syft
    command = f"syft {directory} -o json > {output_file}"
    os.system(command)
    print(f"Generated SBOM: {output_file}")

def scan_vulnerabilities(sbom_file, output_file):
    # https://github.com/anchore/grype
    command = f"grype sbom:{sbom_file} -o json > {output_file}"
    os.system(command)
    print(f"Vulnerability scan saved to {output_file}")

def get_cve_details(cve_id, retries=3):
    for attempt in range(retries):
        # https://nvd.nist.gov/developers/vulnerabilities
        # https://nvd.nist.gov/vuln/detail/CVE-2020-7765
        response = requests.get(f"{nvd_api_url}?cveId={cve_id}&resultsPerPage=1", headers=nvd_headers)
        
        if response.status_code == 200:
            try:
                data = response.json()
                cve_data = data["vulnerabilities"][0]["cve"]
                return {
                    "cveId": cve_data["id"],
                    "publishedDate": cve_data.get("published", "N/A"),
                    "version": cve_data.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("version", "N/A"),
                    "vectorString": cve_data.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("vectorString", "N/A"),
                    "baseScore": cve_data.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A"),
                    "impactScore": cve_data.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("impactScore", "N/A")
                }
            except (KeyError, IndexError):
                return {}
        
        elif response.status_code == 403:
            print(f"403 Forbidden: {cve_id} Attempt {attempt+1}/{retries} - Retrying...")
            time.sleep(20)

    return {}

def analyze_vulnerabilities(grype_output, tag):
    with open(grype_output, "r", encoding='utf-8') as f:
        data = json.load(f)
    
    cve_analysis = {}  # Dictionary to store CVE details with additional information
    
    # Iterate over the matches and related vulnerabilities
    for match in data.get("matches", []):
        artifact_name = match.get("artifact", {}).get("name")
        artifact_version = match.get("artifact", {}).get("version")
        cve_urls = match.get("vulnerability", {}).get("urls", [])
        
        related_vulns = match.get("relatedVulnerabilities", [])
        
        for vuln in related_vulns:
            cve_id = vuln.get("id")
            if cve_id:
                # If the CVE is not already in the analysis, initialize it
                if cve_id not in cve_analysis:
                    cve_analysis[cve_id] = {
                        "cve_id": cve_id,
                        "artifact_name": artifact_name,
                        "artifact_version": artifact_version,
                        "urls": cve_urls
                    }
                # If already present, append the artifact details to match the current entry
                else:
                    cve_analysis[cve_id]["artifact_name"] = artifact_name
                    cve_analysis[cve_id]["artifact_version"] = artifact_version
                    cve_analysis[cve_id]["urls"].extend(cve_urls)

    # Create a list of CVEs with added artifact details
    cve_ids_list = [{"cve_id": cve_id, 
                     "artifact_name": details["artifact_name"], 
                     "artifact_version": details["artifact_version"], 
                     "urls": details["urls"]} 
                    for cve_id, details in cve_analysis.items()]
    
    # Save the CVE analysis with the added details
    with open(f"{tag}.cve_analysis.json", "w", encoding='utf-8') as f:
        json.dump(cve_ids_list, f, indent=4)
    
    print(f"CVE analysis saved to {tag}.cve_analysis.json")
    return cve_ids_list

def main():
    repo_full_name = "tensorflow/tensorflow" # vercel/next.js - tensorflow/tensorflow
    releases = get_recent_releases(repo_full_name)
    
    for release in releases:
        tag = release["tag_name"]
        tarball_url = release["tarball_url"]
        tar_path = f"{tag}.tar.gz"
        extract_to = f"{tag}"
        sbom_file = f"{tag}.sbom.json"
        grype_output = f"{tag}.grype.json"
        
        if download_tarball(tarball_url, tar_path):
            extract_tarball(tar_path, extract_to)
            generate_sbom(extract_to, sbom_file)
            scan_vulnerabilities(sbom_file, grype_output)
            analyze_vulnerabilities(grype_output, tag)

if __name__ == "__main__":
    main()