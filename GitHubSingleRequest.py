import requests
import time
import json
import csv
from collections import defaultdict
from datetime import datetime, timedelta

GITHUB_API_URL = "https://api.github.com"
GITHUB_TOKEN = ""
HEADERS = {
    "Accept": "application/vnd.github.v3+json",
    "Authorization": f"Bearer { GITHUB_TOKEN }",
}

DAYS_AGO = (datetime.now() - timedelta(days=365)).isoformat() + "Z"

def get_default_branch(repo_full_name):
    url = f"{GITHUB_API_URL}/repos/{repo_full_name}"
    response = requests.get(url, headers=HEADERS)

    if response.status_code == 200:
        return response.json().get("default_branch", "master")
    else:
        print(f"Error fetching default branch for {repo_full_name}: {response.status_code}, {response.text}")
        return "master"
    
def get_all_merges(repo_full_name):
    branch = get_default_branch(repo_full_name)
    print(f"Fetching merges for {repo_full_name} on branch: {branch}")

    merges_per_day = defaultdict(int)
    page = 1

    while True:
        url = (f"{GITHUB_API_URL}/repos/{repo_full_name}/commits?"
               f"per_page=100&page={page}&sha={branch}")
        response = requests.get(url, headers=HEADERS)

        if response.status_code == 403:
            print("Rate limit reached. Sleeping for 60 seconds...")
            time.sleep(60)
            continue
        elif response.status_code == 409:
            return {}

        if response.status_code != 200:
            print(f"Error fetching merges for {repo_full_name}: {response.status_code}, {response.text}")
            return None

        commits = response.json()
        if not commits:
            break

        for commit in commits:
            # Check if it's a merge commit (2+ parents)
            if len(commit.get("parents", [])) > 1:
                merge_date = commit["commit"]["committer"]["date"][:10]
                merges_per_day[merge_date] += 1

        page += 1
        time.sleep(1)

    return dict(merges_per_day)
    
def get_recent_merges(repo_full_name):
    branch = get_default_branch(repo_full_name)
    print(f"Fetching merges for {repo_full_name} on branch: {branch}")

    merges_per_day = defaultdict(int)
    page = 1

    while True:
        url = (f"{GITHUB_API_URL}/repos/{repo_full_name}/commits?"
               f"per_page=100&page={page}&since={DAYS_AGO}&sha={branch}")
        response = requests.get(url, headers=HEADERS)

        if response.status_code == 403:
            print("Rate limit reached. Sleeping for 60 seconds...")
            time.sleep(60)
            continue
        elif response.status_code == 409:
            return {}

        if response.status_code != 200:
            print(f"Error fetching merges for {repo_full_name}: {response.status_code}, {response.text}")
            return None

        commits = response.json()
        if not commits:
            break

        for commit in commits:
            # Check if it's a merge commit (2+ parents)
            if len(commit.get("parents", [])) > 1:
                merge_date = commit["commit"]["committer"]["date"][:10]
                merges_per_day[merge_date] += 1

        page += 1
        time.sleep(1)

    return dict(merges_per_day)

def get_all_commits(repo_full_name):
    print(f"Fetching commits for {repo_full_name}")
    commits_per_day = defaultdict(int)
    page = 1

    while True:
        url = f"{GITHUB_API_URL}/repos/{repo_full_name}/commits?per_page=100&page={page}"
        response = requests.get(url, headers=HEADERS)

        if response.status_code == 403:
            print("Rate limit reached. Sleeping for 60 seconds...")
            time.sleep(60)
            continue
        elif response.status_code == 409:
            return {}

        if response.status_code != 200:
            print(f"Error fetching commits for {repo_full_name}: {response.status_code}, {response.text}")
            return None

        commits = response.json()
        if not commits:
            break

        for commit in commits:
            commit_date = commit["commit"]["committer"]["date"][:10]
            commits_per_day[commit_date] += 1

        page += 1
        time.sleep(1)

    return dict(commits_per_day)


def get_recent_commits(repo_full_name):
    print(f"Fetching commits for {repo_full_name}")
    commits_per_day = defaultdict(int)
    page = 1

    while True:
        url = f"{GITHUB_API_URL}/repos/{repo_full_name}/commits?per_page=100&page={page}&since={DAYS_AGO}"
        response = requests.get(url, headers=HEADERS)

        if response.status_code == 403:  # Rate limit
            print("Rate limit reached. Sleeping for 60 seconds...")
            time.sleep(60)
            continue
        elif response.status_code == 409:  # Empty repository
            return {}

        if response.status_code != 200:
            print(f"Error fetching commits for {repo_full_name}: {response.status_code}, {response.text}")
            return None

        commits = response.json()
        if not commits:
            break

        for commit in commits:
            commit_date = commit["commit"]["committer"]["date"][:10]
            commits_per_day[commit_date] += 1

        page += 1
        time.sleep(1)

    return dict(commits_per_day)

def get_all_security_advisories(repo_full_name):
    print(f"Fetching Security Advisories of: {repo_full_name}")
    """Fetches all security advisories for a given repository."""
    advisories = []
    page = 1

    while page <= 43:
        url = f"{GITHUB_API_URL}/repos/{repo_full_name}/security-advisories?per_page=100&sort=updated&page={page}"
        response = requests.get(url, headers=HEADERS)

        if response.status_code == 403:
            print(f"Access denied for security advisories in {repo_full_name}. Requires admin access.")
            return []
        elif response.status_code == 404:
            print(f"No public security advisories found for {repo_full_name}.")
            return []
        elif response.status_code != 200:
            print(f"Error fetching advisories for {repo_full_name}: {response.status_code}, {response.text}")
            return None

        repo_advisories = response.json()
        if not repo_advisories:
            break  # Stop if no more advisories

        for advisory in repo_advisories:
            advisories.append({
                "ghsa_id": advisory.get("ghsa_id"),
                "cve_id": advisory.get("cve_id"),
                "html_url": advisory.get("html_url"),
                "published_at": advisory.get("published_at"),
                "summary": advisory.get("summary"),
                "severity": advisory.get("severity"),
                "vulnerabilities": [
                    {
                        "package": vuln.get("package", {}).get("ecosystem"),
                        "vulnerable_version_range": vuln.get("vulnerable_version_range"),
                        "vulnerable_functions": vuln.get("vulnerable_functions", [])
                    }
                    for vuln in advisory.get("vulnerabilities", [])
                ],
                "cvss_3": {
                        "vector_string": advisory.get("cvss", {}).get("cvss_v3", {}).get("vector_string"),
                        "score": advisory.get("cvss", {}).get("cvss_v3", {}).get("score")
                    },
                "cvss_4": {
                        "vector_string": advisory.get("cvss", {}).get("cvss_v4", {}).get("vector_string"),
                        "score": advisory.get("cvss", {}).get("cvss_v4", {}).get("score")
                    },
                "cwe_ids": advisory.get("cwe_ids", []),
                "updated_at": advisory.get("updated_at")
            })

        page += 1  # Go to the next page
        time.sleep(1)  # Avoid hitting API rate limits

    return advisories

def get_recent_security_advisories(repo_full_name):
    print(f"Fetching Security Advisories of: {repo_full_name}")
    url = f"{GITHUB_API_URL}/repos/{repo_full_name}/security-advisories?per_page=100&sort=published"
    response = requests.get(url, headers=HEADERS)

    if response.status_code == 403:
        print(f"Access denied for security advisories in {repo_full_name}. Requires admin access.")
        return []
    elif response.status_code == 404:
        print(f"No public security advisories found for {repo_full_name}.")
        return []
    elif response.status_code != 200:
        print(f"Error fetching advisories for {repo_full_name}: {response.status_code}, {response.text}")
        return None

    advisories = []
    for advisory in response.json():
        published_at = advisory.get("published_at")

        if published_at and published_at >= DAYS_AGO:
            advisories.append({
                "ghsa_id": advisory.get("ghsa_id"),
                "cve_id": advisory.get("cve_id"),
                "html_url": advisory.get("html_url"),
                "summary": advisory.get("summary"),
                "severity": advisory.get("severity"),
                "vulnerabilities": [
                    {
                        "package": vuln.get("package", {}).get("ecosystem"),
                        "vulnerable_version_range": vuln.get("vulnerable_version_range"),
                        "vulnerable_functions": vuln.get("vulnerable_functions", [])
                    }
                    for vuln in advisory.get("vulnerabilities", [])
                ],
                "cvss_3": {
                        "vector_string": advisory.get("cvss", {}).get("cvss_v3", {}).get("vector_string"),
                        "score": advisory.get("cvss", {}).get("cvss_v3", {}).get("score")
                    },
                "cvss_4": {
                        "vector_string": advisory.get("cvss", {}).get("cvss_v4", {}).get("vector_string"),
                        "score": advisory.get("cvss", {}).get("cvss_v4", {}).get("score")
                    },
                "cwe_ids": advisory.get("cwe_ids", []),
                "updated_at": advisory.get("updated_at"),
                "published_at": advisory.get("published_at")
            })

    return advisories

def get_most_forked_repos():
    print("Fetching most forked repositories on GitHub...")
    url = f"{GITHUB_API_URL}/search/repositories?q=stars:>0&sort=forks&order=desc&per_page=100"
    response = requests.get(url, headers=HEADERS)
    
    if response.status_code != 200:
        print(f"Error fetching most forked repositories: {response.status_code}, {response.text}")
        return None
    
    repos = []
    for repo in response.json().get("items", []):
        repos.append({
            "name": repo.get("name"),
            "full_name": repo.get("full_name"),
            "html_url": repo.get("html_url"),
            "forks_count": repo.get("forks_count"),
            "stargazers_count": repo.get("stargazers_count"),
            "description": repo.get("description")
        })
    
    return repos

def save_to_json(data, filename="commit_data.json"):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    print(f"Commit data saved to {filename}")

def main():
    print("Fetching top repositories...")

    top_repos = [{"name": "tensorflow/tensorflow", "url": "https://github.com/tensorflow/tensorflow"}]

    #top_repos = get_most_forked_repos()
    #save_to_json(top_repos, "top_repos.json")

    repo_commits_data = {}
    repo_merges_data = {}

    repo_data = {}
    repo_advisory_data = {}

    for repo in top_repos:
        """
        commits = get_recent_security_advisories(repo["name"])

        if advisories is not None:
            repo_commits_data[repo["name"]] = commits
            save_to_json(repo_commits_data, "repo_commit_data.json")

        merges = get_recent_security_advisories(repo["name"])

        if advisories is not None:
            repo_merges_data[repo["name"]] = merges
            save_to_json(repo_merges_data, "repo_merge_data.json")

        """

        advisories = get_all_security_advisories(repo["name"])

        if advisories is not None:
            repo_advisory_data[repo["name"]] = advisories
            save_to_json(repo_advisory_data, "security_advisories.json")

        """ 
       if commits_per_day is not None and merges_per_day is not None:
            repo_data[repo["name"]] = {
                "commits": commits_per_day,
                "merges": merges_per_day
            }
        """
        time.sleep(2)

    #save_to_json(repo_data, "repo_commits_merges_data.json")
    #save_to_json(repo_advisory_data, "security_advisories.json")

if __name__ == "__main__":
    if not GITHUB_TOKEN:
        raise Exception("GitHub token not found! Set GITHUB_TOKEN environment variable.")
    
    #https://docs.github.com/en/rest/commits/commits?apiVersion=2022-11-28
    #https://docs.github.com/en/rest/security-advisories/repository-advisories?apiVersion=2022-11-28#list-repository-security-advisories
    main()