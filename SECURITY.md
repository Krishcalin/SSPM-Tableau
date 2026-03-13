# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, email **security@your-org.com** with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to provide a fix within 7 days for critical issues.

## Scope

This policy covers the SSPM scanner code itself. For vulnerabilities in Tableau Cloud, report to [Salesforce Security](https://www.salesforce.com/company/security/).

## Security Considerations

This tool handles sensitive credentials (Tableau PATs). When using it:

- **Never commit `.env` files or PAT secrets to version control** — the `.gitignore` blocks `.env` by default
- **Use environment variables or CI/CD secrets** for credentials in automated pipelines
- **Rotate PATs regularly** — the scanner itself checks for PAT hygiene
- **Restrict PAT scope** — the scanner only needs read access
- **Review scan output before sharing** — reports contain usernames, data source names, and configuration details

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |
