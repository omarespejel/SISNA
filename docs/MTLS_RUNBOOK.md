# mTLS Certificate Rotation and Rollback Runbook

Last updated: 2026-02-13

## Scope

This runbook covers zero-downtime certificate rotation for the keyring proxy in production mode:

- `KEYRING_TRANSPORT=https`
- `KEYRING_MTLS_REQUIRED=true`
- `KEYRING_TLS_CERT_PATH`, `KEYRING_TLS_KEY_PATH`, `KEYRING_TLS_CA_PATH`

## Preconditions

1. Staging environment mirrors production transport settings.
2. Monitoring is enabled for:
- TLS handshake failures
- 401/403 auth failures
- 5xx spikes
3. At least one healthy previous proxy version is available for rollback.
4. Client certificates are inventory-tracked by service owner.

## Rotation strategy

Use overlap windows. Do not do single-step CA replacement.

### Phase 1: Prepare new CA/certs

1. Issue new server cert signed by new CA.
2. Issue new client certs for each authorized client.
3. Validate SANs/validity periods before deployment.

### Phase 2: Trust overlap rollout

1. Update proxy CA bundle to trust both old and new CAs.
2. Restart one canary proxy instance.
3. Verify:
- Existing clients (old certs) still connect.
- New client cert can connect.
4. Roll to remaining instances.

### Phase 3: Client cert rollout

1. Rotate client certs one service at a time.
2. For each client:
- Deploy new cert
- Run smoke sign request
- Confirm no handshake/auth errors

### Phase 4: Deprecate old CA

1. Remove old CA from proxy trust bundle.
2. Restart canary instance and run smoke tests.
3. Roll to full fleet.

## Validation checklist

1. Valid client cert succeeds.
2. Unknown CA cert fails TLS handshake.
3. Expired cert fails TLS handshake.
4. Revoked/removed client cert fails TLS handshake.
5. HMAC auth still enforced after TLS success.

## Rollback

Rollback trigger examples:

- Elevated handshake failures after rollout
- Unexpected 5xx increase
- Inability for critical client to sign

Rollback steps:

1. Restore previous CA bundle and server cert files.
2. Restart canary instance.
3. Validate critical client sign flow.
4. Rollback remaining instances.
5. Keep new certs disabled until root cause is resolved.

## Post-rotation evidence

Record and attach:

1. Cert fingerprints (old/new)
2. Rotation start/end timestamps
3. Service health metrics snapshot
4. Staging + production smoke test logs
5. Any incident notes and follow-up actions
