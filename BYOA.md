# BYOA — Bring Your Own Agent (SISNA)

> One file. One command. Any agent. GitHub-native coordination for a security-critical signer service.

## Quick Start

```bash
gh repo clone omarespejel/SISNA && cd SISNA && cat BYOA.md
```

Then give your agent this instruction:

```
Read BYOA.md in this repository and execute the protocol. You are an OpenClaw agent.
```

## Agent Identity

Set an identity and sign every comment with it:

```bash
AGENT_ID="agent-$(date +%s)-$RANDOM"
echo "I am ${AGENT_ID}"
```

All comments should start with:

`🤖 **${AGENT_ID}**`

## Repository Context

- **Repo:** `omarespejel/SISNA`
- **Stack:** TypeScript, Express, Vitest
- **Mission:** Hardened signer boundary for Starknet session-key execution
- **Primary gate:** `npm test`
- **Security CI:** `.github/workflows/security.yml`

Read `agents.md` before claiming work.

## Sync Protocol

GitHub issues/PRs are the only coordination bus.

### Labels (State Machine)

| Label | Meaning |
|---|---|
| `⚡ open` | available to claim |
| `🤖 claimed` | currently owned by one agent |
| `🔧 wip` | implementation active |
| `👀 needs-review` | ready for review |
| `✅ reviewed` | reviewed by another agent |
| `🚫 blocked` | waiting on decision/dependency |
| `💀 stale-claim` | reclaimable due to inactivity |

### Loop

1. Observe open issues and open PR review queue
2. Review first (unblock others)
3. Claim one issue
4. Implement + test
5. Open PR
6. Loop

## Claim Protocol

```bash
ISSUE=42
REPO="omarespejel/SISNA"

# confirm unclaimed first
gh issue view $ISSUE -R $REPO --json labels

# claim
gh issue comment $ISSUE -R $REPO --body "🤖 **${AGENT_ID}** claiming this issue. Starting now."
gh issue edit $ISSUE -R $REPO --add-label "🤖 claimed" --remove-label "⚡ open"
```

Race rule: earliest timestamp wins.

## Implementation Protocol

```bash
ISSUE=42
REPO="omarespejel/SISNA"

gh issue edit $ISSUE -R $REPO --add-label "🔧 wip" --remove-label "🤖 claimed"

git checkout -b agent/${AGENT_ID}/${ISSUE}-short-desc

# implement and test
npm test

git push -u origin HEAD

gh pr create -R $REPO \
  --title "fix(#${ISSUE}): <concise description>" \
  --body "## Summary
Closes #${ISSUE}

## What changed
<description>

## Verification
npm test

## Agent
\`${AGENT_ID}\`" \
  --label "👀 needs-review"

gh issue comment $ISSUE -R $REPO --body "🤖 **${AGENT_ID}** opened PR. Ready for review."
gh issue edit $ISSUE -R $REPO --remove-label "🔧 wip"
```

## Review Protocol

- never review your own PR
- verify security invariants before approval:
  - HMAC and replay checks preserved
  - authz boundaries preserved
  - no secret leakage in logs/errors
  - policy checks still reject forbidden calls
- `npm test` passes

Approve or request changes with actionable file-level feedback.

## Security-First Rules

- No secrets in code, logs, tests, or fixtures
- No weakening auth/policy checks without explicit issue discussion
- No silent catch/ignore on security-sensitive paths
- Keep PRs focused; one issue per PR

## Blockers

When blocked:

```bash
gh issue comment $ISSUE -R $REPO --body "🤖 **${AGENT_ID}** 🚫 BLOCKED:
**Need:** <question>
**Tried:** <attempts>
**Options:** <A vs B>"
gh issue edit $ISSUE -R $REPO --add-label "🚫 blocked"
```

Then move to another issue.

---

Ship high-signal changes. Keep the signer boundary strict.
