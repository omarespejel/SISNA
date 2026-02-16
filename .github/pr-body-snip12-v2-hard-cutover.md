## What
Hard-cut session signing to strict SNIP-12 v2 semantics and align signer hash construction with the updated `session-account` contract path.

Why now:
- Dfns-backed Starknet signing requires typed-data mode (`Snip12`) and the previous hash semantics were drift-prone across boundaries.
- We need deterministic domain separation across SISNA, starkclaw, and starknet-agentic.

## Spec impact
Breaking compatibility with legacy session hash semantics.

Migration notes:
1. Response payload now includes additive metadata fields:
   - `signatureMode: "v2_snip12"`
   - `domainHash`
2. Signature array format remains `[session_pubkey, r, s, valid_until]` for client compatibility.
3. This PR is compatible only with the paired `starknet-agentic` SNIP-12 v2 contract changes and `starkclaw` v2-only signer behavior.

## Cross-repo impact
Affected repos:
1. `SISNA` (this PR): signer hash + route metadata + tests.
2. `keep-starknet-strange/starknet-agentic`: strict v2 validation/hash on contract side.
3. `keep-starknet-strange/starkclaw`: v2-only runtime signer path.

Boundary change acknowledgment:
- Yes, this is a signer boundary change and requires coordinated deploy/merge with counterpart repos above.

## Security rationale
Threat-model improvements:
1. Enforces domain-separated session message hash (`"StarkNet Message"` wrapper + domain hash + contract binding + payload hash).
2. Reduces replay/confusion risk from ambiguous hash construction.
3. Preserves low-s canonicalization to prevent signature malleability.
4. Adds explicit response metadata (`signatureMode`, `domainHash`, `messageHash`) for auditability/correlation.

Failure mode if bypassed:
- If counterpart contract/client is not upgraded, signatures may be rejected or cross-repo behavior may drift.

## Validation
- [x] `npm run build`
- [x] `npm test`

Executed evidence:
1. `npm test` -> `10` files passed, `61` tests passed.
2. `npm run build` -> TypeScript build passed.

## Risk notes
1. Breaking change at signer-contract boundary if deployed independently.
2. Rollout plan:
   - Merge/deploy in lockstep with `starknet-agentic` and `starkclaw`.
   - Keep deploy window small and monitor signing failures.
3. Rollback plan:
   - Revert this PR and redeploy previous signer version.
   - Revert paired contract/client PRs if already deployed together.

## Checklist
- [x] No secret leakage in logs/errors
- [x] Replay/auth controls preserve invariants
- [x] API/spec changes include migration notes
- [x] Cross-repo compatibility reviewed for boundary changes
