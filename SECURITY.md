# Security Policy

## Supported Versions

This repository is pre-1.0 and currently supports the latest `main` branch only.

## Reporting a Vulnerability

Please report vulnerabilities privately via GitHub security advisories for this repository.

If private reporting is unavailable, contact the maintainers directly and avoid public disclosure
until a fix and coordinated release are ready.

Include:
- impact and affected component(s)
- reproduction steps or proof of concept
- suggested remediation (if available)

## Operational Security Notes

- `SESSION_PRIVATE_KEY` and `KEYRING_SIGNING_KEYS_JSON` load keys into process memory.
  For production, prefer an external signer/KMS/HSM pattern.
- In production mode (`NODE_ENV=production`), TLS + mTLS are mandatory.
- When Redis is used in production, `KEYRING_REDIS_URL` must use `rediss://`.
