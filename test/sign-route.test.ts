import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ec, hash } from "starknet";
import { createApp } from "../src/app.js";
import { buildSigningPayload, computeHmacHex } from "../src/auth/hmac.js";
import type { AppConfig } from "../src/config.js";
import { SessionTransactionSigner } from "../src/signer/sessionSigner.js";

const baseConfig: AppConfig = {
  NODE_ENV: "test",
  PORT: 8545,
  HOST: "127.0.0.1",
  KEYRING_TRANSPORT: "http",
  KEYRING_MTLS_REQUIRED: false,
  LOG_LEVEL: "error",
  KEYRING_DEFAULT_AUTH_CLIENT_ID: "mcp-default",
  AUTH_CLIENTS: [
    {
      clientId: "mcp-default",
      hmacSecret: "not-a-real-hmac-secret-change-me-0001",
      allowedKeyIds: ["default"],
    },
    {
      clientId: "mcp-ops",
      hmacSecret: "not-a-real-hmac-secret-change-me-0002",
      allowedKeyIds: ["ops"],
    },
  ],
  KEYRING_MAX_SKEW_MS: 60_000,
  KEYRING_NONCE_TTL_MS: 120_000,
  KEYRING_MAX_VALIDITY_WINDOW_SEC: 24 * 60 * 60,
  KEYRING_ALLOWED_CHAIN_IDS: [],
  KEYRING_REPLAY_STORE: "memory",
  KEYRING_REDIS_NONCE_PREFIX: "starknet-keyring-proxy:nonce:",
  KEYRING_RATE_LIMIT_ENABLED: false,
  KEYRING_RATE_LIMIT_BACKEND: "memory",
  KEYRING_RATE_LIMIT_WINDOW_MS: 60_000,
  KEYRING_RATE_LIMIT_MAX_REQUESTS: 120,
  KEYRING_REDIS_RATE_LIMIT_PREFIX: "starknet-keyring-proxy:ratelimit:",
  KEYRING_LEAK_SCANNER_ENABLED: false,
  KEYRING_LEAK_SCANNER_ACTION: "block",
  KEYRING_ALLOW_INSECURE_IN_PROCESS_KEYS_IN_PRODUCTION: false,
  KEYRING_SECURITY_PROFILE: "flex",
  KEYRING_SIGNER_PROVIDER: "local",
  KEYRING_SIGNER_FALLBACK_PROVIDER: "none",
  KEYRING_DFNS_TIMEOUT_MS: 7000,
  KEYRING_SESSION_SIGNATURE_MODE: "v2_snip12",
  KEYRING_DEFAULT_KEY_ID: "default",
  SIGNING_KEYS: [
    {
      keyId: "default",
      privateKey: "0x1",
      publicKey: undefined,
    },
    {
      keyId: "ops",
      privateKey: "0x2",
      publicKey: undefined,
    },
  ],
};

const validBody = {
  accountAddress: "0x111",
  chainId: "0x534e5f5345504f4c4941",
  nonce: "0x1",
  validUntil: Math.floor(Date.now() / 1000) + 3600,
  calls: [
    {
      contractAddress: "0x222",
      entrypoint: "transfer",
      calldata: ["0xabc", "0x1", "0x0"],
    },
  ],
};

function authHeaders(
  bodyRaw: string,
  nonce: string,
  opts?: { timestamp?: number; clientId?: string; secret?: string },
) {
  const timestamp = opts?.timestamp ?? Date.now();
  const clientId = opts?.clientId ?? baseConfig.KEYRING_DEFAULT_AUTH_CLIENT_ID;
  const clientSecret = opts?.secret
    ?? baseConfig.AUTH_CLIENTS.find((client) => client.clientId === clientId)?.hmacSecret
    ?? "";
  const ts = String(timestamp);
  const payload = buildSigningPayload({
    timestamp: ts,
    nonce,
    method: "POST",
      path: "/v1/sign/session-transaction",
      rawBody: bodyRaw,
  });
  const signature = computeHmacHex(clientSecret, payload);

  return {
    "x-keyring-client-id": clientId,
    "x-keyring-timestamp": ts,
    "x-keyring-nonce": nonce,
    "x-keyring-signature": signature,
    "content-type": "application/json",
  };
}

function buildDfnsSignatureResponse(
  bodyRequest: typeof validBody,
  privateKey: string,
  overrides?: Partial<{
    domainHash: string;
    messageHash: string;
  }>,
) {
  const signer = new SessionTransactionSigner(
    [{ keyId: "default", privateKey, publicKey: undefined }],
    "default",
    new Map(),
    new Map(),
    { maxValidityWindowSec: 24 * 60 * 60, allowedChainIds: new Set() },
  );
  const signed = signer.sign(bodyRequest as any, "test-client");
  return {
    signatureMode: "v2_snip12" as const,
    signatureKind: "Snip12" as const,
    signerProvider: "dfns" as const,
    sessionPublicKey: signed.sessionPublicKey,
    domainHash: overrides?.domainHash ?? signed.domainHash,
    messageHash: overrides?.messageHash ?? signed.messageHash,
    signature: signed.signature,
  };
}

describe("sign route", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("serves unauthenticated health without stack fingerprinting", async () => {
    const app = createApp(baseConfig);
    const res = await request(app).get("/health");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
    expect(res.headers["x-powered-by"]).toBeUndefined();
  });

  it("blocks requests that include an Origin header", async () => {
    const app = createApp(baseConfig);
    const bodyRaw = JSON.stringify(validBody);
    const res = await request(app)
      .post("/v1/sign/session-transaction")
      .set(authHeaders(bodyRaw, "nonce-origin-blocked"))
      .set("origin", "https://example.com")
      .send(bodyRaw);

    expect(res.status).toBe(403);
    expect(res.body.error).toContain("browser origins");
  });

  it("blocks health endpoint requests that include an Origin header", async () => {
    const app = createApp(baseConfig);
    const res = await request(app)
      .get("/health")
      .set("origin", "https://example.com");

    expect(res.status).toBe(403);
  });

  it("returns 401 without auth headers", async () => {
    const app = createApp(baseConfig);
    const res = await request(app).post("/v1/sign/session-transaction").send(validBody);
    expect(res.status).toBe(401);
  });

  it("returns a 4-felt signature for valid request", async () => {
    const app = createApp(baseConfig);
    const bodyRaw = JSON.stringify(validBody);

    const res = await request(app)
      .post("/v1/sign/session-transaction")
      .set(authHeaders(bodyRaw, "nonce-1"))
      .send(bodyRaw);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.signature)).toBe(true);
    expect(res.body.signature.length).toBe(4);
    expect(res.body.signatureMode).toBe("v2_snip12");
    expect(res.body.signatureKind).toBe("Snip12");
    expect(res.body.signerProvider).toBe("local");
    expect(typeof res.body.domainHash).toBe("string");
    expect(/^0x[0-9a-f]+$/i.test(res.body.domainHash)).toBe(true);
    expect(typeof res.body.messageHash).toBe("string");
    expect(/^0x[0-9a-f]+$/i.test(res.body.messageHash)).toBe(true);
    expect(res.body.sessionPublicKey).toBe(ec.starkCurve.getStarkKey("0x1"));
  });

  it("accepts dfns signer responses only when hashes match the request payload", async () => {
    const fetchMock = vi.fn(async (_url: unknown, init: any) => {
      const parsedBody = JSON.parse(String(init.body)) as {
        request: typeof validBody;
        kind: string;
        signatureMode: string;
      };
      const headers = init.headers as Record<string, string>;
      expect(headers.authorization).toBe("Bearer dfns-auth-token");
      expect(headers["x-dfns-useraction"]).toBe("dfns-useraction-signature");
      expect(parsedBody.kind).toBe("Snip12");
      expect(parsedBody.signatureMode).toBe("v2_snip12");
      return {
        ok: true,
        json: async () => buildDfnsSignatureResponse(parsedBody.request, "0x1"),
      } as any;
    });
    vi.stubGlobal("fetch", fetchMock);

    const app = createApp({
      ...baseConfig,
      KEYRING_SIGNER_PROVIDER: "dfns",
      KEYRING_SIGNER_FALLBACK_PROVIDER: "none",
      KEYRING_DFNS_SIGNER_URL: "https://dfns-signer.internal/sign",
      KEYRING_DFNS_AUTH_TOKEN: "dfns-auth-token",
      KEYRING_DFNS_USER_ACTION_SIGNATURE: "dfns-useraction-signature",
    });
    const bodyRaw = JSON.stringify(validBody);
    const res = await request(app)
      .post("/v1/sign/session-transaction")
      .set(authHeaders(bodyRaw, "nonce-dfns-ok"))
      .send(bodyRaw);

    expect(res.status).toBe(200);
    expect(res.body.signatureMode).toBe("v2_snip12");
    expect(res.body.signatureKind).toBe("Snip12");
    expect(res.body.signerProvider).toBe("dfns");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("rejects dfns signer responses when domain/message hashes do not match request payload", async () => {
    const fetchMock = vi.fn(async (_url: unknown, init: any) => {
      const parsedBody = JSON.parse(String(init.body)) as {
        request: typeof validBody;
      };
      return {
        ok: true,
        json: async () =>
          buildDfnsSignatureResponse(parsedBody.request, "0x1", {
            messageHash: "0x1234",
          }),
      } as any;
    });
    vi.stubGlobal("fetch", fetchMock);

    const app = createApp({
      ...baseConfig,
      KEYRING_SIGNER_PROVIDER: "dfns",
      KEYRING_SIGNER_FALLBACK_PROVIDER: "none",
      KEYRING_DFNS_SIGNER_URL: "https://dfns-signer.internal/sign",
      KEYRING_DFNS_AUTH_TOKEN: "dfns-auth-token",
      KEYRING_DFNS_USER_ACTION_SIGNATURE: "dfns-useraction-signature",
    });
    const bodyRaw = JSON.stringify(validBody);
    const res = await request(app)
      .post("/v1/sign/session-transaction")
      .set(authHeaders(bodyRaw, "nonce-dfns-bad-hash"))
      .send(bodyRaw);

    expect(res.status).toBe(503);
    expect(res.body.error).toBe("signer unavailable");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("supports explicit keyId while keeping same endpoint", async () => {
    const app = createApp(baseConfig);
    const body = {
      ...validBody,
      keyId: "ops",
    };
    const bodyRaw = JSON.stringify(body);

    const res = await request(app)
      .post("/v1/sign/session-transaction")
      .set(authHeaders(bodyRaw, "nonce-key-ops", { clientId: "mcp-ops" }))
      .send(bodyRaw);

    expect(res.status).toBe(200);
    expect(res.body.sessionPublicKey).toBe(ec.starkCurve.getStarkKey("0x2"));
  });

  it("rejects unknown keyId", async () => {
    const app = createApp(baseConfig);
    const body = {
      ...validBody,
      keyId: "does-not-exist",
    };
    const bodyRaw = JSON.stringify(body);

    const res = await request(app)
      .post("/v1/sign/session-transaction")
      .set(authHeaders(bodyRaw, "nonce-key-missing"))
      .send(bodyRaw);

    expect(res.status).toBe(422);
    expect(res.body.error).toContain("keyId");
  });

  it("rejects unknown client id", async () => {
    const app = createApp(baseConfig);
    const bodyRaw = JSON.stringify(validBody);

    const res = await request(app)
      .post("/v1/sign/session-transaction")
      .set(authHeaders(bodyRaw, "nonce-unknown-client", {
        clientId: "ghost-client",
        secret: "not-a-real-hmac-secret-change-me-0003",
      }))
      .send(bodyRaw);

    expect(res.status).toBe(401);
    expect(res.body.error).toContain("unknown client");
  });

  it("rejects client using unauthorized keyId", async () => {
    const app = createApp(baseConfig);
    const body = {
      ...validBody,
      keyId: "ops",
    };
    const bodyRaw = JSON.stringify(body);

    const res = await request(app)
      .post("/v1/sign/session-transaction")
      .set(authHeaders(bodyRaw, "nonce-key-forbidden", { clientId: "mcp-default" }))
      .send(bodyRaw);

    expect(res.status).toBe(422);
    expect(res.body.error).toContain("not allowed");
  });

  it("rejects replayed nonce", async () => {
    const app = createApp(baseConfig);
    const bodyRaw = JSON.stringify(validBody);
    const headers = authHeaders(bodyRaw, "nonce-replay");

    const first = await request(app)
      .post("/v1/sign/session-transaction")
      .set(headers)
      .send(bodyRaw);
    expect(first.status).toBe(200);

    const second = await request(app)
      .post("/v1/sign/session-transaction")
      .set(headers)
      .send(bodyRaw);
    expect(second.status).toBe(401);
    expect(second.body.error).toContain("replayed nonce");
  });

  it("does not consume nonce when HMAC signature is invalid", async () => {
    const app = createApp(baseConfig);
    const bodyRaw = JSON.stringify(validBody);
    const nonce = "nonce-invalid-hmac-then-valid";
    const invalidHeaders = {
      ...authHeaders(bodyRaw, nonce),
      "x-keyring-signature": "00".repeat(32),
    };

    const first = await request(app)
      .post("/v1/sign/session-transaction")
      .set(invalidHeaders)
      .send(bodyRaw);
    expect(first.status).toBe(401);
    expect(first.body.error).toContain("invalid signature");

    const second = await request(app)
      .post("/v1/sign/session-transaction")
      .set(authHeaders(bodyRaw, nonce))
      .send(bodyRaw);
    expect(second.status).toBe(200);
  });

  it("rejects stale timestamp", async () => {
    const app = createApp(baseConfig);
    const bodyRaw = JSON.stringify(validBody);
    const oldTs = Date.now() - 120_000;

    const res = await request(app)
      .post("/v1/sign/session-transaction")
      .set(authHeaders(bodyRaw, "nonce-old-ts", { timestamp: oldTs }))
      .send(bodyRaw);

    expect(res.status).toBe(401);
    expect(res.body.error).toContain("outside accepted window");
  });

  it("rejects oversized auth headers", async () => {
    const app = createApp(baseConfig);
    const bodyRaw = JSON.stringify(validBody);
    const res = await request(app)
      .post("/v1/sign/session-transaction")
      .set(authHeaders(bodyRaw, "n".repeat(129)))
      .send(bodyRaw);

    expect(res.status).toBe(401);
    expect(res.body.error).toContain("header too large");
  });

  it("rejects self-calls with policy error", async () => {
    const app = createApp(baseConfig);
    const body = {
      ...validBody,
      calls: [
        {
          contractAddress: validBody.accountAddress,
          entrypoint: "transfer",
          calldata: ["0xabc", "0x1", "0x0"],
        },
      ],
    };
    const bodyRaw = JSON.stringify(body);

    const res = await request(app)
      .post("/v1/sign/session-transaction")
      .set(authHeaders(bodyRaw, "nonce-2"))
      .send(bodyRaw);

    expect(res.status).toBe(422);
    expect(res.body.error).toContain("self-call");
  });

  it("rejects self-calls with equivalent felt values (leading-zero variant)", async () => {
    const app = createApp(baseConfig);
    const body = {
      ...validBody,
      calls: [
        {
          contractAddress: "0x0111",
          entrypoint: "transfer",
          calldata: ["0xabc", "0x1", "0x0"],
        },
      ],
    };
    const bodyRaw = JSON.stringify(body);

    const res = await request(app)
      .post("/v1/sign/session-transaction")
      .set(authHeaders(bodyRaw, "nonce-self-leading-zero"))
      .send(bodyRaw);

    expect(res.status).toBe(422);
    expect(res.body.error).toContain("self-call");
  });

  it("rejects denied selectors even on external targets", async () => {
    const app = createApp(baseConfig);
    const body = {
      ...validBody,
      calls: [
        {
          contractAddress: "0x999",
          entrypoint: "set_agent_id",
          calldata: ["0x1"],
        },
      ],
    };
    const bodyRaw = JSON.stringify(body);

    const res = await request(app)
      .post("/v1/sign/session-transaction")
      .set(authHeaders(bodyRaw, "nonce-denied-selector"))
      .send(bodyRaw);

    expect(res.status).toBe(422);
    expect(res.body.error).toContain("denied selector");
  });

  it("rejects denied selectors in hex form with leading zeros", async () => {
    const app = createApp(baseConfig);
    const deniedSelector = hash.getSelectorFromName("set_agent_id");
    const body = {
      ...validBody,
      calls: [
        {
          contractAddress: "0x999",
          entrypoint: `0x00${deniedSelector.slice(2)}`,
          calldata: ["0x1"],
        },
      ],
    };
    const bodyRaw = JSON.stringify(body);

    const res = await request(app)
      .post("/v1/sign/session-transaction")
      .set(authHeaders(bodyRaw, "nonce-denied-selector-leading-zero"))
      .send(bodyRaw);

    expect(res.status).toBe(422);
    expect(res.body.error).toContain("denied selector");
  });

  it("rejects already expired validUntil", async () => {
    const app = createApp(baseConfig);
    const body = {
      ...validBody,
      validUntil: Math.floor(Date.now() / 1000) - 10,
    };
    const bodyRaw = JSON.stringify(body);

    const res = await request(app)
      .post("/v1/sign/session-transaction")
      .set(authHeaders(bodyRaw, "nonce-expired-vu"))
      .send(bodyRaw);

    expect(res.status).toBe(422);
    expect(res.body.error).toContain("validUntil");
  });

  it("rejects validUntil too far in the future", async () => {
    const app = createApp(baseConfig);
    const body = {
      ...validBody,
      validUntil: Math.floor(Date.now() / 1000) + (25 * 60 * 60),
    };
    const bodyRaw = JSON.stringify(body);

    const res = await request(app)
      .post("/v1/sign/session-transaction")
      .set(authHeaders(bodyRaw, "nonce-too-far-vu"))
      .send(bodyRaw);

    expect(res.status).toBe(422);
    expect(res.body.error).toContain("exceeds maximum");
  });

  it("rejects disallowed chain id when allowlist is configured", async () => {
    const app = createApp({
      ...baseConfig,
      KEYRING_ALLOWED_CHAIN_IDS: ["0x534e5f4d41494e"],
    });
    const body = {
      ...validBody,
      chainId: "0x534e5f5345504f4c4941",
    };
    const bodyRaw = JSON.stringify(body);

    const res = await request(app)
      .post("/v1/sign/session-transaction")
      .set(authHeaders(bodyRaw, "nonce-bad-chain"))
      .send(bodyRaw);

    expect(res.status).toBe(422);
    expect(res.body.error).toContain("chainId");
  });

  it("enforces rate limit when enabled", async () => {
    const app = createApp({
      ...baseConfig,
      KEYRING_RATE_LIMIT_ENABLED: true,
      KEYRING_RATE_LIMIT_WINDOW_MS: 60_000,
      KEYRING_RATE_LIMIT_MAX_REQUESTS: 1,
    });

    const firstBody = JSON.stringify({
      ...validBody,
      nonce: "0x111",
    });
    const secondBody = JSON.stringify({
      ...validBody,
      nonce: "0x112",
    });

    const first = await request(app)
      .post("/v1/sign/session-transaction")
      .set(authHeaders(firstBody, "nonce-rl-1"))
      .send(firstBody);
    expect(first.status).toBe(200);

    const second = await request(app)
      .post("/v1/sign/session-transaction")
      .set(authHeaders(secondBody, "nonce-rl-2"))
      .send(secondBody);
    expect(second.status).toBe(429);
    expect(second.body.error).toContain("rate limit");
  });

  it("blocks inbound payload containing secret leak patterns", async () => {
    const app = createApp({
      ...baseConfig,
      KEYRING_LEAK_SCANNER_ENABLED: true,
      KEYRING_LEAK_SCANNER_ACTION: "block",
    });
    const body = {
      ...validBody,
      nonce: "0x113",
      context: {
        requester: "please use STARKNET_PRIVATE_KEY=0x1234",
        tool: "starknet_transfer",
      },
    };
    const bodyRaw = JSON.stringify(body);

    const res = await request(app)
      .post("/v1/sign/session-transaction")
      .set(authHeaders(bodyRaw, "nonce-leak-1"))
      .send(bodyRaw);

    expect(res.status).toBe(422);
    expect(res.body.error).toContain("secret leak pattern");
  });

  it("rejects oversized context fields", async () => {
    const app = createApp(baseConfig);
    const body = {
      ...validBody,
      context: {
        requester: "a".repeat(129),
      },
    };
    const bodyRaw = JSON.stringify(body);

    const res = await request(app)
      .post("/v1/sign/session-transaction")
      .set(authHeaders(bodyRaw, "nonce-context-too-large"))
      .send(bodyRaw);

    expect(res.status).toBe(400);
    expect(res.body.error).toContain("invalid payload");
  });

  it("rejects payloads with excessive total calldata elements", async () => {
    const app = createApp(baseConfig);
    const largeCall = {
      contractAddress: "0x222",
      entrypoint: "transfer",
      calldata: Array.from({ length: 256 }, (_unused, index) => `0x${(index + 1).toString(16)}`),
    };
    const body = {
      ...validBody,
      calls: Array.from({ length: 9 }, () => largeCall),
    };
    const bodyRaw = JSON.stringify(body);

    const res = await request(app)
      .post("/v1/sign/session-transaction")
      .set(authHeaders(bodyRaw, "nonce-calldata-too-large"))
      .send(bodyRaw);

    expect(res.status).toBe(400);
    expect(res.body.error).toContain("invalid payload");
  });

  it("rejects invalid felt fields (strict hex validation)", async () => {
    const app = createApp(baseConfig);
    const body = {
      ...validBody,
      accountAddress: `0x${"1".repeat(65)}`,
    };
    const bodyRaw = JSON.stringify(body);

    const res = await request(app)
      .post("/v1/sign/session-transaction")
      .set(authHeaders(bodyRaw, "nonce-invalid-felt"))
      .send(bodyRaw);

    expect(res.status).toBe(400);
    expect(res.body.error).toContain("invalid payload");
    expect(res.body.details?.fieldErrors?.accountAddress?.length ?? 0).toBeGreaterThan(0);
  });

  it("enforces JSON body size limit (256kb)", async () => {
    const app = createApp(baseConfig);
    const body = {
      ...validBody,
      context: { reason: "a".repeat(300_000) },
    };
    const bodyRaw = JSON.stringify(body);

    const res = await request(app)
      .post("/v1/sign/session-transaction")
      .set(authHeaders(bodyRaw, "nonce-body-too-large"))
      .send(bodyRaw);

    expect(res.status).toBe(413);
  });
});
