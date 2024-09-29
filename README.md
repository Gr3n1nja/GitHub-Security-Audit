# GitHub-Security-Audit
Automate the security review of your GitHub organizations with **GitHub-Security-Audit**. This tool provides detailed checks on organization members, code owners, repository settings, and ensures compliance with best security practices.

## Purpose
The script `GitHubSecAudit.py` is designed to automate the review of security configurations within GitHub organizations. It helps identify and report on several key security settings, ensuring that organization members, code owners, and repository configurations adhere to best practices in security management.

## What the Script Checks
- **Organization Members**: Retrieves all members of the organization to ensure only authorized users have access.
- **Code Owners**: Lists the admins set as code owners, crucial for managing approvals and merge permissions.
- **Repositories**: Fetches all repositories within the organization to audit their settings.
- **CODEOWNERS File**: Checks each repository for the presence and validity of a `.github/CODEOWNERS` file, which is essential for protecting branches and defining who can review and contribute to specific parts of the codebase.
  - **Multi-location check**: The script now checks for the `CODEOWNERS` file in `.github/`, the repository root, and `docs/` directories.
  - **Branch check**: It looks for the `CODEOWNERS` file in both the `master` and `main` branches and reports if neither is present.

## Prerequisites
Before running the script, ensure you have the following prerequisites installed and set up:

- **Python 3.x**: The script is written in Python and requires Python 3.
- **Requests Library**: This Python library is used for making HTTP requests. Install it via pip:
  ```bash
  pip3 install requests
  ```

- **GitHub Token**: You need a personal access token with appropriate permissions to access organization details on GitHub. Set this token as an environment variable:
  - For Linux/Mac:
    ```bash
    export GITHUB_TOKEN='your_token_here'
    ```
  - For Windows Command Prompt:
    ```cmd
    set GITHUB_TOKEN=your_token_here
    ```
  - For Windows PowerShell:
    ```powershell
    $env:GITHUB_TOKEN="your_token_here"
    ```

## Execution
To execute the script, navigate to the directory containing `GitHubSecAudit.py` and run:
```bash
python3 GitHubSecAudit.py your_org_name
```
Replace `your_org_name` with the actual name of your GitHub organization.

## Output
The script provides the following output:
- **Members**: A list of all organization members.
- **Code Owners**: A list of all organization admins who are set as code owners.
- **Repository CODEOWNERS Status**: The presence and validity of the `CODEOWNERS` file in each repository, including checks for both `master` and `main` branches, as well as multiple locations (`.github/`, root, and `docs/`).

## Additional Security Checks
The script currently checks for members, code owners, and `.github/CODEOWNERS` file statuses. Future enhancements will include:
- **Branch Protection Rules**: Ensuring branches have the necessary protection settings to safeguard against unauthorized changes.

## Scanning Repositories for Hardcoded Credentials
To scan your repositories for hardcoded credentials, which is outside the scope of this script, consider using specialized tools such as:
- [Nosey Parker](https://github.com/praetorian-inc/noseyparker)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog)

These tools are more suited for detecting sensitive information inadvertently pushed to version control systems.
