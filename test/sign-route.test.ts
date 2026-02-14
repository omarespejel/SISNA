import request from "supertest";
import { describe, expect, it } from "vitest";
import { ec } from "starknet";
import { createApp } from "../src/app.js";
import { buildSigningPayload, computeHmacHex } from "../src/auth/hmac.js";
import type { AppConfig } from "../src/config.js";

const baseConfig: AppConfig = {
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

describe("sign route", () => {
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
    expect(res.body.sessionPublicKey).toBe(ec.starkCurve.getStarkKey("0x1"));
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

  it("rejects invalid felt fields (strict hex validation)", async () => {
    const app = createApp(baseConfig);
    const body = {
      ...validBody,
      accountAddress: `0x${"1".repeat(65)}`, // >32 bytes
    };
    const bodyRaw = JSON.stringify(body);

    const res = await request(app)
      .post("/v1/sign/session-transaction")
      .set(authHeaders(bodyRaw, "nonce-invalid-felt"))
      .send(bodyRaw);

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid payload");
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
