import os
import argparse
import base64
import requests
import urllib3

GITHUB_API = "https://api.github.com"
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def parse_arguments():
    parser = argparse.ArgumentParser(description='Access and manage GitHub organization details.')
    parser.add_argument('org_name', help='Name of the GitHub organization.')
    return parser.parse_args()

def check_github_token():
    token = os.getenv('GITHUB_TOKEN')
    if not token:
        print("Error: GitHub token not set in environment variables.")
        print("Please set the GITHUB_TOKEN variable before running this script.")
        print("For example, on Linux or Mac: export GITHUB_TOKEN='your_token_here'")
        print("Or on Windows Command Prompt: set GITHUB_TOKEN=your_token_here")
        exit(1)
    return token

def create_headers(token):
    return {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json'
    }

def get_org_members(org_name, headers):
    url = f'{GITHUB_API}/orgs/{org_name}/members'
    members = []
    while url:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
        members.extend(response.json())
        url = response.links.get('next', {}).get('url')
    return members

def get_org_codeowners(org_name, headers):
    url = f'{GITHUB_API}/orgs/{org_name}/members?role=admin'
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    admins = response.json()
    return [admin['login'] for admin in admins]

def get_org_repos(org_name, headers):
    url = f'{GITHUB_API}/orgs/{org_name}/repos'
    repos = []
    while url:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
        repos.extend(response.json())
        url = response.links.get('next', {}).get('url')
    return repos

def check_codeowners_file(org_name, repo_name, headers):
    branches_to_check = ['master', 'main']
    locations_to_check = ['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS']
    branch_status = {}

    for branch in branches_to_check:
        branch_status[branch] = "Not Set (File Missing)"  # Default status for branch

        for location in locations_to_check:
            url = f'{GITHUB_API}/repos/{org_name}/{repo_name}/contents/{location}?ref={branch}'
            response = requests.get(url, headers=headers, verify=False)

            if response.status_code == 200:
                codeowners_content = response.json().get('content')
                if codeowners_content:
                    decoded_content = base64.b64decode(codeowners_content).decode('utf-8')
                    return "Set and Valid" if decoded_content.strip() else "Set but Invalid (Empty)"
            elif response.status_code != 404:
                return f"Error Checking {location} in {branch} branch"
    
    return "CODEOWNERS Not Set on both 'master' and 'main'"

def main():
    args = parse_arguments()
    token = check_github_token()
    headers = create_headers(token)
    members = get_org_members(args.org_name, headers)
    codeowners = get_org_codeowners(args.org_name, headers)
    repos = get_org_repos(args.org_name, headers)
    codeowners_status = {repo['name']: check_codeowners_file(args.org_name, repo['name'], headers) for repo in repos}
    
    print("Members:", [member['login'] for member in members])
    print("Code Owners:", codeowners)
    print("Repository CODEOWNERS Status:", codeowners_status)

if __name__ == "__main__":
    main()
