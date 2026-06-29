# Security Policy

## Authorized Use

NetScope is intended only for systems and networks you own or have explicit written permission to assess. Public target scanning is blocked unless the operator passes explicit authorization flags.

## Reporting a Vulnerability

If you find a security issue in NetScope itself, open a private advisory or contact the maintainer before publishing details. Include:

- Affected version or commit
- Reproduction steps
- Impact
- Suggested fix, if known

## Handling Sensitive Output

Reports can contain hostnames, banners, software versions, CVEs, and network topology. Store `reports/` and `logs/` in access-controlled locations and avoid committing generated artifacts.

## Secrets

Do not commit `config/settings.yaml`, `.env`, API keys, or scan reports. The Docker build context excludes these by default through `.dockerignore`.
