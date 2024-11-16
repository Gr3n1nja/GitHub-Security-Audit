# GitHub-Security-Audit

Automate the security review of your GitHub organizations with **GitHub-Security-Audit**. This tool provides detailed checks on organization members, code owners, repository settings, and ensures compliance with best security practices.

## Purpose

The script `GitHubSecAudit.py` is designed to automate the review of security configurations within GitHub organizations. It helps identify and report on several key security settings, ensuring that organization members, code owners, and repository configurations adhere to best practices in security management.

## What the Script Checks

1. **Organization Members**: Retrieves all members of the organization to ensure only authorized users have access.
2. **Code Owners**: Lists the admins set as code owners, crucial for managing approvals and merge permissions.
3. **Repositories**: Fetches all repositories within the organization to audit their settings.
4. **CODEOWNERS File**:
   - **Multi-location Check**: The script checks for the `CODEOWNERS` file in `.github/`, the repository root, and `docs/` directories.
   - **Branch Check**: It looks for the `CODEOWNERS` file in the default branch (`main` or `master`) and reports if the file is missing or invalid.
5. **Branch Protection Rules**:
   - Ensures branches follow critical security configurations:
     - **Pull Request Approvals**: Minimum `2+` approvals required.
     - **Signed Commits**: Ensure commit signatures are enforced.
     - **Enforce Admin Rules**: Admins should follow branch rules.
     - **Disable Force Pushes**: Prevent risky force pushes.
     - **Disable Deletions**: Protect against accidental or malicious deletions.
     - **Required Conversation Resolution**: Ensure all conversations are resolved before merging.

## Prerequisites

Before running the script, ensure you have the following prerequisites installed and set up:

- **Python 3.x**: The script is written in Python and requires Python 3.
- **Requests Library**: Install the library for making HTTP requests:
  
      pip3 install requests

- **urllib3**: Install the library for handling HTTP connections:

      pip3 install urllib3

- **GitHub Token**: You need a personal access token with appropriate permissions to access organization details on GitHub. Set this token as an environment variable:

  - For Linux/Mac:

        export GITHUB_TOKEN='your_token_here'

  - For Windows Command Prompt:

        set GITHUB_TOKEN=your_token_here

  - For Windows PowerShell:

        $env:GITHUB_TOKEN="your_token_here"

- **Update API Endpoint**: If your GitHub organization uses a custom API endpoint (e.g., for an enterprise GitHub instance), update the `GITHUB_API_URL` in the script accordingly.

### Permissions & API Rate Limits:

- **Required Permissions**:  
  Ensure your GitHub token has the following permissions:
  - `read:org` - To access organization member details.
  - `repo` - To fetch repository and branch protection settings.
  - `admin:repo_hook` - If auditing repository hooks in future enhancements.

- **Rate Limits**:  
  GitHub API enforces rate limits depending on authentication:
  - **Authenticated Requests**: Limited to 5,000 requests per hour per user.
  - **Unauthenticated Requests**: Limited to 60 requests per hour.  
  If rate limits are hit, consider:
  - Using a token with elevated API limits.
  - Optimizing script execution for fewer requests.

## Execution

Run the script as follows:

    python3 GitHubSecAudit.py --org_name <organization_name>

Optional:

    python3 GitHubSecAudit.py --org_name <organization_name> --api_url <api_url>

Replace `<organization_name>` with the name of your GitHub organization and `<api_url>` with your custom API endpoint if applicable.

## Output

The script generates a comprehensive HTML report summarizing the audit results:

1. **Summary**:
   - Total Repositories
   - Total Members
   - Total Code Owners
2. **Detailed Report**:
   - Repository Name
   - Configuration (e.g., PR Approvals Required, Signed Commits, etc.)
   - Current Value
   - Expected Value
   - Status (Correct/Incorrect)

The HTML report is saved to the same directory with the name `<org_name>_audit_report.html`.

### Features of the HTML Report

- **Interactive Filters**: Filter by Repository Name, Configuration, Status, Current Value, or Expected Value.
- **Modals for Details**: View detailed lists of organization members and code owners through clickable modals.
- **Color-Coded Status**: Correct configurations are highlighted in green, while incorrect ones are highlighted in red.

## Additional Security Checks

This script ensures security compliance for GitHub organizations by:

- Verifying branch protection rules.
- Auditing `CODEOWNERS` file status and validity.

## Limitations

- Requires appropriate API permissions for full functionality.
- Focuses only on auditing branch protection rules and repository configurations.

## Future Enhancements Will Include:

- **Additional Security Checks**: Expand to include checks like dependency vulnerabilities, 2FA enforcement, and branch activity monitoring.
- **Export Results**: Provide an option to export audit results in CSV or Excel formats for easy sharing and analysis.
- **Collaborator Roles**: Identify external collaborators with elevated permissions and assess their access levels.

## Troubleshooting

If you encounter issues:

1. Verify your personal access token has the required permissions.
2. Ensure the organization or repository exists and is accessible.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
