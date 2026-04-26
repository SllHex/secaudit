# Security Policy

## Supported Versions

SecAudit is currently maintained as a single active branch. Security fixes are applied to the latest tagged release line.

## Reporting Security Issues

If you discover a security issue in SecAudit itself, please avoid opening a public exploit-style issue first.

Share:

- affected version
- reproduction steps
- impact
- a minimal proof of concept, if safe

This project is intended for defensive, non-intrusive auditing only. Reports about adding offensive functionality, exploit automation, brute force features, or bypass tooling will not be accepted.

## Safe Usage

SecAudit is designed for:

- external validation of public-facing targets you own or are authorized to assess
- CI/CD posture checks
- non-destructive misconfiguration detection

It must not be used to:

- brute-force credentials
- trigger denial-of-service conditions
- attempt exploit chains
- bypass authentication
- perform unauthorized scanning
