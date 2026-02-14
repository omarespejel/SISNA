<identity>
Multi-agent coordination for SISNA (security-critical signer boundary, fast but disciplined iteration).
</identity>

<roles>
| Role | Owns | Does NOT |
| ---- | ---- | -------- |
| Coordinator | issue sequencing, integration status, release notes | ship large feature PRs directly |
| Auth Executor | HMAC/authz/replay pathways | modify policy engine silently |
| Policy Executor | call validation, selector guards, chain/validUntil checks | weaken auth boundary |
| Transport Executor | TLS/mTLS/runtime env hardening | change signing semantics without review |
| Reviewer | correctness, security invariants, regression safety | author + approve same PR |
</roles>

<delegation>
For each work item:
1. Investigation: affected files, acceptance checks, security impact.
2. Execution: minimal implementation with tests.
3. Review: verify invariants and run `npm test`.
</delegation>

<task_states>
todo -> inprogress -> inreview -> done
blocked can be entered from any state when waiting on a decision/dependency
</task_states>

<parallelization>
SAFE to parallelize:
- docs/tests work vs independent policy modules
- replay backend improvements vs API docs updates

MUST serialize:
- changes touching auth headers + middleware + signing route together
- anything that changes request/response contract in `docs/api-spec.yaml`

Conflict resolution:
1. detect overlap early (`rg` touched files)
2. land shared-interface changes first
3. rebase dependent work and rerun tests
</parallelization>

<integration_protocol>
- prefer short-lived branches and frequent merges
- no direct merge without tests and reviewer signoff
- keep PR scope narrow and security-auditable
- update docs when behavior changes
</integration_protocol>

<security_invariants>
- HMAC auth must remain mandatory on signing route
- nonce replay protection must remain one-time and bounded by TTL
- authz must bind `clientId` to allowed `keyId` set
- policy validation must reject denied selectors and self-target calls
- no secret material in logs/errors
</security_invariants>

<escalation>
Escalate when:
- a decision changes API contract or signer trust boundary
- security controls are relaxed or bypassed
- infra choice affects replay/rate-limit guarantees

Format:
## Escalation: [Title]
**Blocker**: [...]
**Options**:
1. [...]
2. [...]
**Recommendation**: [...]
</escalation>
