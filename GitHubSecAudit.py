#!/usr/bin/env python3

import base64
import requests
import urllib3
import datetime
import argparse
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def parse_arguments():
    parser = argparse.ArgumentParser(
        description=(
            "GitHub Security Audit Tool\n\n"
            "Usage Examples:\n"
            "  python3 test2.py --org_name <organization_name>\n"
            "  python3 test2.py --org_name <organization_name> --api_url <api_url>"
        ),
        epilog="Ensure the GITHUB_TOKEN environment variable is set before running.",
    )
    parser.add_argument(
        '--org_name',
        required=True,
        help="The GitHub organization or username to audit."
    )
    parser.add_argument(
        '--api_url',
        default='https://api.github.com',
        help="Optional: The GitHub API URL (default: https://api.github.com)."
    )
    return parser.parse_args()

def check_github_token():
    token = os.getenv('GITHUB_TOKEN')
    if not token:
        print("Error: GitHub token not set in environment variables.")
        print("Please set the GITHUB_TOKEN variable before running this script.")
        print("For example:")
        print("  - On Linux/Mac: export GITHUB_TOKEN='your_token_here'")
        print("  - On Windows Command Prompt: set GITHUB_TOKEN=your_token_here")
        print("  - On Windows PowerShell: $env:GITHUB_TOKEN=\"your_token_here\"")
        exit(1)
    return token

args = parse_arguments()
GITHUB_TOKEN = check_github_token()
GITHUB_API_URL = args.api_url
ORG_NAME = args.org_name

headers = {
    'Authorization': f'token {GITHUB_TOKEN}',
    'Accept': 'application/vnd.github.v3+json'
}

def is_organization(org_name):
    url = f"{GITHUB_API_URL}/users/{org_name}"
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 403:
        return 'Permission Denied'
    response.raise_for_status()
    user_data = response.json()
    return user_data.get('type') == 'Organization'

def get_org_members(org_name):
    if is_organization(org_name) == 'Permission Denied':
        return 'Permission Denied'
    if not is_organization(org_name):
        return [{'login': org_name}]

    url = f'{GITHUB_API_URL}/orgs/{org_name}/members'
    members = []
    while url:
        response = requests.get(url, headers=headers, verify=False)
        if response.status_code == 403:
            return 'Permission Denied'
        response.raise_for_status()
        members.extend(response.json())
        url = response.links.get('next', {}).get('url')
    return members

def get_org_codeowners(org_name):
    if not is_organization(org_name):
        return []
    url = f'{GITHUB_API_URL}/orgs/{org_name}/members?role=admin'
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 403:
        return 'Permission Denied'
    response.raise_for_status()
    admins = response.json()
    return [admin['login'] for admin in admins]

def get_org_repos(org_name):
    org_type = is_organization(org_name)
    if org_type == 'Permission Denied':
        return 'Permission Denied'
    url = f'{GITHUB_API_URL}/orgs/{org_name}/repos' if org_type else f'{GITHUB_API_URL}/users/{org_name}/repos'

    repos = []
    while url:
        response = requests.get(url, headers=headers, verify=False)
        if response.status_code == 403:
            return 'Permission Denied'
        response.raise_for_status()
        repos.extend(response.json())
        url = response.links.get('next', {}).get('url')
    return repos

def get_default_branch(org_name, repo_name):
    url = f"{GITHUB_API_URL}/repos/{org_name}/{repo_name}"
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    repo_data = response.json()
    return repo_data.get("default_branch", "main")

def check_codeowners_file(org_name, repo_name):
    default_branch = get_default_branch(org_name, repo_name)
    locations_to_check = ['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS']
    branch_status = "Not Set (File Missing)"

    for location in locations_to_check:
        url = f'{GITHUB_API_URL}/repos/{org_name}/{repo_name}/contents/{location}?ref={default_branch}'
        response = requests.get(url, headers=headers, verify=False)

        if response.status_code == 200:
            codeowners_content = response.json().get('content')
            if codeowners_content:
                decoded_content = base64.b64decode(codeowners_content).decode('utf-8')
                branch_status = "Set and Valid" if decoded_content.strip() else "Set but Invalid (Empty)"
                break
        elif response.status_code == 403:
            branch_status = "Permission Denied"
            break
        elif response.status_code != 404:
            branch_status = f"Error Checking {location} for {default_branch} branch"
            break

    return {default_branch: branch_status}

def check_branch_protection(org_name, repo_name):
    default_branch = get_default_branch(org_name, repo_name)
    url = f'{GITHUB_API_URL}/repos/{org_name}/{repo_name}/branches/{default_branch}/protection'
    response = requests.get(url, headers=headers, verify=False)

    if response.status_code == 200:
        protection_data = response.json()
        
        pr_reviews = protection_data.get('required_pull_request_reviews', {})
        required_approvals = pr_reviews.get('required_approving_review_count', 0)
        dismiss_stale_reviews = "Enabled" if pr_reviews.get('dismiss_stale_reviews', False) else "Disabled"
        
        signed_commits = "Enabled" if protection_data.get('required_signatures', {}).get('enabled', False) else "Disabled"
        enforce_admins = "Enabled" if protection_data.get('enforce_admins', {}).get('enabled', False) else "Disabled"

        allow_force_pushes = "Enabled" if protection_data.get('allow_force_pushes', {}).get('enabled', False) else "Disabled"
        allow_deletions = "Enabled" if protection_data.get('allow_deletions', {}).get('enabled', False) else "Disabled"

        conversation_resolution = "Enabled" if protection_data.get('required_conversation_resolution', {}).get('enabled', False) else "Disabled"

        return {
            'Branch': default_branch,
            'PR Approvals Required': required_approvals,
            'Dismiss Stale Reviews': dismiss_stale_reviews,
            'Signed Commits': signed_commits,
            'Enforce Admins': enforce_admins,
            'Allow Force Pushes': allow_force_pushes,
            'Allow Deletions': allow_deletions,
            'Required Conversation Resolution': conversation_resolution
        }
    elif response.status_code == 404:
        return {default_branch: "No Protection"}
    elif response.status_code == 403:
        return {default_branch: "Permission Denied"}
    else:
        return {default_branch: f"Error Checking Protection ({response.status_code})"}

def get_branch_protection_summary(org_name, repos):
    protection_summary = {}

    for repo in repos:
        repo_name = repo['name']
        branch_protection = check_branch_protection(org_name, repo_name)
        protection_summary[repo_name] = branch_protection

    return protection_summary

def generate_html_report(org_name, members, codeowners, codeowners_status, branch_protection_summary):
    report_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html_content = f"""
    <html>
        <head>
            <title>{org_name} GitHub Audit Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
                h1, h2 {{ color: #333; }}
                .summary-table, .details-table {{ width: 60%; border-collapse: collapse; margin-bottom: 20px; }}
                .summary-table th, .summary-table td, .details-table th, .details-table td {{ padding: 8px; border: 1px solid #ddd; }}
                .summary-table th, .details-table th {{ background-color: #f4f4f4; text-align: left; }}
                .issue {{ background-color: #f8d7da; color: #721c24; font-weight: bold; }}
                .success {{ background-color: #d4edda; color: #155724; font-weight: bold; }}
                .section {{ margin-bottom: 30px; }}
                /* Column width adjustments */
                .details-table th, .details-table td {{ white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
                .col-repo {{ width: 200px; }}
                .col-config {{ width: 150px; }}
                .col-status {{ width: 100px; }}
                .col-value {{ width: 120px; }}
                .modal {{ display: none; position: fixed; z-index: 1; padding-top: 60px; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.4); }}
                .modal-content {{ background-color: #fefefe; margin: auto; padding: 20px; border: 1px solid #888; width: 60%; }}
                .close {{ color: #aaa; float: right; font-size: 28px; font-weight: bold; }}
                .close:hover, .close:focus {{ color: black; text-decoration: none; cursor: pointer; }}
            </style>
            <!-- DataTables CSS and JS for sorting, pagination, searching, and column filtering -->
            <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.11.5/css/jquery.dataTables.min.css"/>
            <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/buttons/1.7.1/css/buttons.dataTables.min.css"/>
            <script type="text/javascript" src="https://code.jquery.com/jquery-3.5.1.js"></script>
            <script type="text/javascript" src="https://cdn.datatables.net/1.11.5/js/jquery.dataTables.min.js"></script>
            <script type="text/javascript" src="https://cdn.datatables.net/buttons/1.7.1/js/dataTables.buttons.min.js"></script>
            <script type="text/javascript" src="https://cdn.datatables.net/buttons/1.7.1/js/buttons.html5.min.js"></script>
            <script>
                $(document).ready(function() {{
                    // Initialize DataTable with column-specific filtering
                    var table = $('#detailed-report-table').DataTable({{
                        "pageLength": 10,
                        "lengthMenu": [[10, 25, 50, -1], [10, 25, 50, "All"]],
                        "order": [[0, "asc"]],
                        "initComplete": function () {{
                            this.api().columns().every(function (index) {{
                                var column = this;
                                var placeholder = ["Repository Name", "Configuration", "Status", "Current Value", "Expected Value"][index];
                                var select = $('<select><option value="">' + placeholder + '</option></select>')
                                    .appendTo($(column.header()).empty())  // Append filter to the header with placeholder
                                    .on('change', function () {{
                                        var val = $.fn.dataTable.util.escapeRegex($(this).val());
                                        column.search(val ? '^' + val + '$' : '', true, false).draw();
                                    }});
                                column.data().unique().sort().each(function (d, j) {{
                                    select.append('<option value="' + d + '">' + d + '</option>')
                                }});
                            }});
                        }}
                    }});

                    // Modal functionality for Members and Code Owners
                    function showModal(modalId) {{
                        document.getElementById(modalId).style.display = "block";
                    }}
                    function closeModal(modalId) {{
                        document.getElementById(modalId).style.display = "none";
                    }}
                    window.showModal = showModal;
                    window.closeModal = closeModal;
                }});
            </script>
        </head>
        <body>
            <h1>{org_name} GitHub Audit Report</h1>
            <p><strong>Summary</strong> (Generated on {report_date})</p>
            <table class="summary-table">
                <tr>
                    <th>Total Repositories</th>
                    <td><a href="javascript:void(0);" onclick="showModal('reposModal')">{len(branch_protection_summary)} (View Repositories)</a></td>
                </tr>
                <tr><th>Total Members</th><td><a href="javascript:void(0);" onclick="showModal('membersModal')">{len(members)} (View Members)</a></td></tr>
                <tr><th>Total Code Owners</th><td><a href="javascript:void(0);" onclick="showModal('codeownersModal')">{len(codeowners)} (View Code Owners)</a></td></tr>
            </table>

            <!-- Modal for Repositories -->
            <div id="reposModal" class="modal">
                <div class="modal-content">
                    <span class="close" onclick="closeModal('reposModal')">&times;</span>
                    <h2>Repository List</h2>
                    <ul>
                        {"".join([f"<li>{repo}</li>" for repo in branch_protection_summary.keys()])}
                    </ul>
                </div>
            </div>

            <!-- Modal for Members -->
            <div id="membersModal" class="modal">
                <div class="modal-content">
                    <span class="close" onclick="closeModal('membersModal')">&times;</span>
                    <h2>Organization Members</h2>
                    <ul>
                        {"".join([f"<li>{member['login']}</li>" for member in members])}
                    </ul>
                </div>
            </div>

            <!-- Modal for Code Owners -->
            <div id="codeownersModal" class="modal">
                <div class="modal-content">
                    <span class="close" onclick="closeModal('codeownersModal')">&times;</span>
                    <h2>Code Owners (Admins)</h2>
                    <ul>
                        {"".join([f"<li>{owner}</li>" for owner in codeowners])}
                    </ul>
                </div>
            </div>

            <h2>Detailed Report</h2>
            <table class="details-table" id="detailed-report-table">
                <thead>
                    <tr>
                        <th class="col-repo">Repository Name</th>
                        <th class="col-config">Configuration</th>
                        <th class="col-status">Status</th>
                        <th class="col-value">Current Value</th>
                        <th class="col-value">Expected Value</th>
                    </tr>
                </thead>
                <tbody>
    """

    for repo, protection_info in branch_protection_summary.items():
        checks = [
            ("PR Approvals Required", protection_info.get('PR Approvals Required', 0), "2+"),
            ("Signed Commits", protection_info.get('Signed Commits', False), "Enabled"),
            ("Enforce Admins", protection_info.get('Enforce Admins', False), "Enabled"),
            ("Allow Force Pushes", protection_info.get('Allow Force Pushes', False), "Disabled"),
            ("Allow Deletions", protection_info.get('Allow Deletions', False), "Disabled"),
            ("Required Conversation Resolution", protection_info.get('Required Conversation Resolution', False), "Enabled"),
        ]

        for config, current, expected in checks:
            status_class = "success" if (
                str(current) == expected or (config == "PR Approvals Required" and current >= 2)
            ) else "issue"
            html_content += f"""
                <tr>
                    <td>{repo}</td>
                    <td>{config}</td>
                    <td class="{status_class}">{'Correct' if status_class == 'success' else 'Incorrect'}</td>
                    <td>{'Enabled' if current is True else 'Disabled' if current is False else current}</td>
                    <td>{expected}</td>
                </tr>
            """

    for repo, status in codeowners_status.items():
        for branch, detail in status.items():
            expected_status = "Set and Valid"
            color_class = "success" if detail == expected_status else "issue"
            html_content += f"""
                <tr>
                    <td>{repo}</td>
                    <td>CODEOWNERS Status</td>
                    <td class='{color_class}'>{'Correct' if color_class == 'success' else 'Incorrect'}</td>
                    <td>{detail}</td>
                    <td>{expected_status}</td>
                </tr>
            """

    html_content += """
                </tbody>
            </table>
        </body>
    </html>
    """
    
    with open(f"{org_name}_audit_report.html", "w") as file:
        file.write(html_content)
    print(f"HTML report saved to {org_name}_audit_report.html")


if __name__ == "__main__":
    repos = get_org_repos(ORG_NAME)
    if repos == 'Permission Denied':
        print("Error: Access to repositories denied.")
    else:
        members = get_org_members(ORG_NAME)
        codeowners = get_org_codeowners(ORG_NAME)
        codeowners_status = {repo['name']: check_codeowners_file(ORG_NAME, repo['name']) for repo in repos}
        branch_protection_summary = get_branch_protection_summary(ORG_NAME, repos)
        
        generate_html_report(ORG_NAME, members, codeowners, codeowners_status, branch_protection_summary)
