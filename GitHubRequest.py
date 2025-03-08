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

TEN_DAYS_AGO = (datetime.now() - timedelta(days=10)).isoformat() + "Z"

def get_top_repositories():
    url = f"{GITHUB_API_URL}/search/repositories?q=stars:>10000&sort=stars&order=desc&per_page=100"
    response = requests.get(url, headers=HEADERS)

    if response.status_code != 200:
        raise Exception(f"Error fetching repositories: {response.status_code}, {response.text}")
    
    repos = response.json()["items"]
    return [{"name": repo["full_name"], "url": repo["html_url"]} for repo in repos]

def get_top_mixed_repositories():
    stars_url = f"{GITHUB_API_URL}/search/repositories?q=stars:>10000&sort=stars&order=desc&per_page=100"
    forks_url = f"{GITHUB_API_URL}/search/repositories?q=forks:>5000&sort=forks&order=desc&per_page=100"

    repos = {}

    # Fetch repositories sorted by stars
    response = requests.get(stars_url, headers=HEADERS)
    if response.status_code == 200:
        for repo in response.json()["items"]:
            repos[repo["full_name"]] = {
                "name": repo["full_name"],
                "url": repo["html_url"],
                "stars": repo["stargazers_count"],
                "forks": repo["forks_count"],
                "score": repo["stargazers_count"] + (2 * repo["forks_count"]),
            }

    # Fetch repositories sorted by forks
    response = requests.get(forks_url, headers=HEADERS)
    if response.status_code == 200:
        for repo in response.json()["items"]:
            if repo["full_name"] not in repos:
                repos[repo["full_name"]] = {
                    "name": repo["full_name"],
                    "url": repo["html_url"],
                    "stars": repo["stargazers_count"],
                    "forks": repo["forks_count"],
                    "score": repo["stargazers_count"] + (2 * repo["forks_count"]),
                }

    # Sort by weighted score and pick the top 10
    top_repos = sorted(repos.values(), key=lambda x: x["score"], reverse=True)[:100]

    return [{"name": repo["name"], "url": repo["url"], "stars": repo["stars"], "forks": repo["forks"], "score": repo["score"]} for repo in top_repos]

def get_default_branch(repo_full_name):
    url = f"{GITHUB_API_URL}/repos/{repo_full_name}"
    response = requests.get(url, headers=HEADERS)

    if response.status_code == 200:
        return response.json().get("default_branch", "master")
    else:
        print(f"Error fetching default branch for {repo_full_name}: {response.status_code}, {response.text}")
        return "master"

def get_recent_merges(repo_full_name):
    branch = get_default_branch(repo_full_name)
    print(f"Fetching merges for {repo_full_name} on branch: {branch}")

    merges_per_day = defaultdict(int)
    page = 1

    while True:
        url = (f"{GITHUB_API_URL}/repos/{repo_full_name}/commits?"
               f"per_page=100&page={page}&since={TEN_DAYS_AGO}&sha={branch}")
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

def get_recent_commits(repo_full_name):
    print(f"Fetching commits for {repo_full_name}")
    commits_per_day = defaultdict(int)
    page = 1

    while True:
        url = f"{GITHUB_API_URL}/repos/{repo_full_name}/commits?per_page=100&page={page}&since={TEN_DAYS_AGO}"
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

def get_all_commits(repo_full_name):
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

def get_public_security_advisories(repo_full_name):
    url = f"{GITHUB_API_URL}/repos/{repo_full_name}/security-advisories?per_page=10&sort=updated"
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
            "cvss": {
                "vector_string": advisory.get("cvss", {}).get("cvss_v4", {}).get("vector_string"),
                "score": advisory.get("cvss", {}).get("cvss_v4", {}).get("score")
            },
            "cwe_ids": advisory.get("cwe_ids", [])
        })

    return advisories

def save_to_json(data, filename="commit_data.json"):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    print(f"Commit data saved to {filename}")

def main():
    print("Fetching top repositories...")
    #top_repos = get_top_repositories()
    top_repos = get_top_mixed_repositories()

    repo_data = {}
    repo_advisory_data = {}

    for repo in top_repos:
        commits_per_day = get_recent_commits(repo["name"])
        merges_per_day = get_recent_merges(repo["name"])
        advisories = get_public_security_advisories(repo["name"])

        """if commits_per_day is not None:
            repo_commit_data[repo["name"]] = commits_per_day"""

        if commits_per_day is not None and merges_per_day is not None:
            repo_data[repo["name"]] = {
                "commits": commits_per_day,
                "merges": merges_per_day
            }

        if advisories is not None:
            repo_advisory_data[repo["name"]] = advisories

        time.sleep(2)

    save_to_json(repo_data, "repo_commit_merge_data.json")
    save_to_json(repo_advisory_data, "security_advisories.json")
                   
if __name__ == "__main__":
    if not GITHUB_TOKEN:
        raise Exception("GitHub token not found! Set GITHUB_TOKEN environment variable.")
    main()