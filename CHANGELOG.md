# Changelog
All notable changes to this repository are documented in this file.

The format is based on Keep a Changelog and this project follows SemVer with a pre-1.0 policy (see `VERSIONING.md`).

## [Unreleased]

## [0.1.0] - 2026-02-14
### Security
- Use server-generated request IDs in signer audit logs.  
  PR: `#1`  
  Merge commit: `72e57d2c6d018b2beccc2328a15a6411ee39c333`
- Hardened auth/policy flow:
  - canonical felt checks
  - HMAC-before-nonce replay hardening  
  PR: `#2`  
  Merge commit: `97f955c8eb3d1826d8b9acf474ed61d70b7bd4af`
- Prevent rate-limit key evasion by removing `context.tool` from bucket key.  
  PR: `#3`  
  Merge commit: `f27c0a28cfb1818ede8855a5a3dc68e86291f082`
- Added CI security gates:
  - gitleaks secret scan
  - dependency audit allowlist gate  
  PR: `#4`  
  Merge commit: `ce75562aab9967d3aa67fe4e0233168b53cc38e8`
- Added request-validation and signer hardening:
  - 256kb body-size limit
  - strict hex felt validation + bounded payload sizes
  - canonical ECDSA `s` normalization
  - regression tests for new controls  
  PR: `#5`  
  Merge commit: `c46f4756a9359800715562c6a57ba1677ee731c7`

