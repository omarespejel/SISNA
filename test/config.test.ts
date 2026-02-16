import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";

function baseEnv(): NodeJS.ProcessEnv {
  return {
    KEYRING_HMAC_SECRET: "not-a-real-hmac-secret-change-me",
  };
}

describe("config loading", () => {
  it("supports backward-compatible single key mode", () => {
    const cfg = loadConfig({
      ...baseEnv(),
      SESSION_PRIVATE_KEY: "0x1",
    });

    expect(cfg.SIGNING_KEYS.length).toBe(1);
    expect(cfg.SIGNING_KEYS[0]?.keyId).toBe("default");
    expect(cfg.KEYRING_DEFAULT_KEY_ID).toBe("default");
    expect(cfg.KEYRING_DEFAULT_AUTH_CLIENT_ID).toBe("default");
    expect(cfg.AUTH_CLIENTS.length).toBe(1);
    expect(cfg.AUTH_CLIENTS[0]?.clientId).toBe("default");
    expect(cfg.KEYRING_REPLAY_STORE).toBe("memory");
    expect(cfg.KEYRING_RATE_LIMIT_ENABLED).toBe(false);
    expect(cfg.KEYRING_LEAK_SCANNER_ENABLED).toBe(false);
    expect(cfg.NODE_ENV).toBe("development");
  });

  it("supports multi-key json mode", () => {
    const cfg = loadConfig({
      ...baseEnv(),
      KEYRING_DEFAULT_KEY_ID: "ops",
      KEYRING_SIGNING_KEYS_JSON:
        '[{"keyId":"default","privateKey":"0x1"},{"keyId":"ops","privateKey":"0x2"}]',
    });

    expect(cfg.SIGNING_KEYS.length).toBe(2);
    expect(cfg.KEYRING_DEFAULT_KEY_ID).toBe("ops");
  });

  it("supports explicit auth clients json config", () => {
    const cfg = loadConfig({
      ...baseEnv(),
      SESSION_PRIVATE_KEY: "0x1",
      KEYRING_DEFAULT_AUTH_CLIENT_ID: "mcp-ops",
      KEYRING_AUTH_CLIENTS_JSON:
        '[{"clientId":"mcp-default","hmacSecret":"not-a-real-hmac-secret-change-me-0001","allowedKeyIds":["default"]},{"clientId":"mcp-ops","hmacSecret":"not-a-real-hmac-secret-change-me-0002"}]',
    });

    expect(cfg.AUTH_CLIENTS.length).toBe(2);
    expect(cfg.KEYRING_DEFAULT_AUTH_CLIENT_ID).toBe("mcp-ops");
  });

  it("rejects duplicate key ids", () => {
    expect(() =>
      loadConfig({
        ...baseEnv(),
        KEYRING_SIGNING_KEYS_JSON:
          '[{"keyId":"default","privateKey":"0x1"},{"keyId":"default","privateKey":"0x2"}]',
      }),
    ).toThrow(/Duplicate keyId/i);
  });

  it("rejects missing default key id in signing keys", () => {
    expect(() =>
      loadConfig({
        ...baseEnv(),
        KEYRING_DEFAULT_KEY_ID: "ops",
        KEYRING_SIGNING_KEYS_JSON: '[{"keyId":"default","privateKey":"0x1"}]',
      }),
    ).toThrow(/KEYRING_DEFAULT_KEY_ID/i);
  });

  it("requires redis url when replay store is redis", () => {
    expect(() =>
      loadConfig({
        ...baseEnv(),
        SESSION_PRIVATE_KEY: "0x1",
        KEYRING_REPLAY_STORE: "redis",
      }),
    ).toThrow(/KEYRING_REDIS_URL/i);
  });

  it("requires redis url when rate limit backend is redis", () => {
    expect(() =>
      loadConfig({
        ...baseEnv(),
        SESSION_PRIVATE_KEY: "0x1",
        KEYRING_RATE_LIMIT_ENABLED: "true",
        KEYRING_RATE_LIMIT_BACKEND: "redis",
      }),
    ).toThrow(/KEYRING_REDIS_URL/i);
  });

  it("accepts redis replay store config", () => {
    const cfg = loadConfig({
      ...baseEnv(),
      SESSION_PRIVATE_KEY: "0x1",
      KEYRING_REPLAY_STORE: "redis",
      KEYRING_REDIS_URL: "redis://localhost:6379",
      KEYRING_REDIS_NONCE_PREFIX: "test:nonce:",
    });

    expect(cfg.KEYRING_REPLAY_STORE).toBe("redis");
    expect(cfg.KEYRING_REDIS_URL).toBe("redis://localhost:6379");
    expect(cfg.KEYRING_REDIS_NONCE_PREFIX).toBe("test:nonce:");
  });

  it("accepts rate limit and leak scanner config", () => {
    const cfg = loadConfig({
      ...baseEnv(),
      SESSION_PRIVATE_KEY: "0x1",
      KEYRING_REDIS_URL: "redis://localhost:6379",
      KEYRING_RATE_LIMIT_ENABLED: "true",
      KEYRING_RATE_LIMIT_BACKEND: "redis",
      KEYRING_RATE_LIMIT_WINDOW_MS: "30000",
      KEYRING_RATE_LIMIT_MAX_REQUESTS: "30",
      KEYRING_REDIS_RATE_LIMIT_PREFIX: "test:rl:",
      KEYRING_LEAK_SCANNER_ENABLED: "true",
      KEYRING_LEAK_SCANNER_ACTION: "warn",
    });

    expect(cfg.KEYRING_RATE_LIMIT_ENABLED).toBe(true);
    expect(cfg.KEYRING_RATE_LIMIT_BACKEND).toBe("redis");
    expect(cfg.KEYRING_RATE_LIMIT_WINDOW_MS).toBe(30000);
    expect(cfg.KEYRING_RATE_LIMIT_MAX_REQUESTS).toBe(30);
    expect(cfg.KEYRING_REDIS_RATE_LIMIT_PREFIX).toBe("test:rl:");
    expect(cfg.KEYRING_LEAK_SCANNER_ENABLED).toBe(true);
    expect(cfg.KEYRING_LEAK_SCANNER_ACTION).toBe("warn");
  });

  it("requires tls cert and key when https transport is enabled", () => {
    expect(() =>
      loadConfig({
        ...baseEnv(),
        SESSION_PRIVATE_KEY: "0x1",
        KEYRING_TRANSPORT: "https",
      }),
    ).toThrow(/KEYRING_TLS_CERT_PATH and KEYRING_TLS_KEY_PATH/i);
  });

  it("requires https transport when mtls is required", () => {
    expect(() =>
      loadConfig({
        ...baseEnv(),
        SESSION_PRIVATE_KEY: "0x1",
        KEYRING_MTLS_REQUIRED: "true",
      }),
    ).toThrow(/requires KEYRING_TRANSPORT=https/i);
  });

  it("requires ca path when mtls is required", () => {
    expect(() =>
      loadConfig({
        ...baseEnv(),
        SESSION_PRIVATE_KEY: "0x1",
        KEYRING_TRANSPORT: "https",
        KEYRING_TLS_CERT_PATH: "/tmp/server.crt",
        KEYRING_TLS_KEY_PATH: "/tmp/server.key",
        KEYRING_MTLS_REQUIRED: "true",
      }),
    ).toThrow(/KEYRING_TLS_CA_PATH/i);
  });

  it("accepts mtls configuration", () => {
    const cfg = loadConfig({
      ...baseEnv(),
      SESSION_PRIVATE_KEY: "0x1",
      KEYRING_TRANSPORT: "https",
      KEYRING_TLS_CERT_PATH: "/tmp/server.crt",
      KEYRING_TLS_KEY_PATH: "/tmp/server.key",
      KEYRING_TLS_CA_PATH: "/tmp/ca.crt",
      KEYRING_MTLS_REQUIRED: "true",
    });

    expect(cfg.KEYRING_TRANSPORT).toBe("https");
    expect(cfg.KEYRING_MTLS_REQUIRED).toBe(true);
    expect(cfg.KEYRING_TLS_CA_PATH).toBe("/tmp/ca.crt");
  });

  it("requires https transport in production", () => {
    expect(() =>
      loadConfig({
        ...baseEnv(),
        NODE_ENV: "production",
        SESSION_PRIVATE_KEY: "0x1",
      }),
    ).toThrow(/NODE_ENV=production requires KEYRING_TRANSPORT=https/i);
  });

  it("requires mTLS in production", () => {
    expect(() =>
      loadConfig({
        ...baseEnv(),
        NODE_ENV: "production",
        SESSION_PRIVATE_KEY: "0x1",
        KEYRING_TRANSPORT: "https",
        KEYRING_TLS_CERT_PATH: "/tmp/server.crt",
        KEYRING_TLS_KEY_PATH: "/tmp/server.key",
      }),
    ).toThrow(/NODE_ENV=production requires KEYRING_MTLS_REQUIRED=true/i);
  });

  it("accepts production profile with https + mTLS", () => {
    const cfg = loadConfig({
      ...baseEnv(),
      NODE_ENV: "production",
      SESSION_PRIVATE_KEY: "0x1",
      KEYRING_TRANSPORT: "https",
      KEYRING_TLS_CERT_PATH: "/tmp/server.crt",
      KEYRING_TLS_KEY_PATH: "/tmp/server.key",
      KEYRING_TLS_CA_PATH: "/tmp/ca.crt",
      KEYRING_MTLS_REQUIRED: "true",
      KEYRING_ALLOW_INSECURE_IN_PROCESS_KEYS_IN_PRODUCTION: "true",
    });

    expect(cfg.NODE_ENV).toBe("production");
    expect(cfg.KEYRING_TRANSPORT).toBe("https");
    expect(cfg.KEYRING_MTLS_REQUIRED).toBe(true);
    expect(cfg.KEYRING_ALLOW_INSECURE_IN_PROCESS_KEYS_IN_PRODUCTION).toBe(true);
  });

  it("requires rediss url in production when redis replay store is enabled", () => {
    expect(() =>
      loadConfig({
        ...baseEnv(),
        NODE_ENV: "production",
        SESSION_PRIVATE_KEY: "0x1",
        KEYRING_TRANSPORT: "https",
        KEYRING_TLS_CERT_PATH: "/tmp/server.crt",
        KEYRING_TLS_KEY_PATH: "/tmp/server.key",
        KEYRING_TLS_CA_PATH: "/tmp/ca.crt",
        KEYRING_MTLS_REQUIRED: "true",
        KEYRING_REPLAY_STORE: "redis",
        KEYRING_REDIS_URL: "redis://localhost:6379",
      }),
    ).toThrow(/KEYRING_REDIS_URL to use rediss/i);
  });

  it("accepts rediss url in production when redis replay store is enabled", () => {
    const cfg = loadConfig({
      ...baseEnv(),
      NODE_ENV: "production",
      SESSION_PRIVATE_KEY: "0x1",
      KEYRING_TRANSPORT: "https",
      KEYRING_TLS_CERT_PATH: "/tmp/server.crt",
      KEYRING_TLS_KEY_PATH: "/tmp/server.key",
      KEYRING_TLS_CA_PATH: "/tmp/ca.crt",
      KEYRING_MTLS_REQUIRED: "true",
      KEYRING_REPLAY_STORE: "redis",
      KEYRING_REDIS_URL: "rediss://localhost:6379",
      KEYRING_ALLOW_INSECURE_IN_PROCESS_KEYS_IN_PRODUCTION: "true",
    });

    expect(cfg.KEYRING_REDIS_URL).toBe("rediss://localhost:6379");
  });

  it("requires explicit insecure key custody acknowledgement in production", () => {
    expect(() =>
      loadConfig({
        ...baseEnv(),
        NODE_ENV: "production",
        SESSION_PRIVATE_KEY: "0x1",
        KEYRING_TRANSPORT: "https",
        KEYRING_TLS_CERT_PATH: "/tmp/server.crt",
        KEYRING_TLS_KEY_PATH: "/tmp/server.key",
        KEYRING_TLS_CA_PATH: "/tmp/ca.crt",
        KEYRING_MTLS_REQUIRED: "true",
      }),
    ).toThrow(/KEYRING_ALLOW_INSECURE_IN_PROCESS_KEYS_IN_PRODUCTION=true/i);
  });

  it("requires auth config via keyring secret or auth clients json", () => {
    expect(() =>
      loadConfig({
        SESSION_PRIVATE_KEY: "0x1",
      }),
    ).toThrow(/No auth clients configured/i);
  });

  it("rejects duplicate auth client ids", () => {
    expect(() =>
      loadConfig({
        ...baseEnv(),
        SESSION_PRIVATE_KEY: "0x1",
        KEYRING_AUTH_CLIENTS_JSON:
          '[{"clientId":"a","hmacSecret":"not-a-real-hmac-secret-change-me-0001"},{"clientId":"a","hmacSecret":"not-a-real-hmac-secret-change-me-0002"}]',
      }),
    ).toThrow(/Duplicate auth client id/i);
  });

  it("rejects auth clients referencing unknown keyId", () => {
    expect(() =>
      loadConfig({
        ...baseEnv(),
        SESSION_PRIVATE_KEY: "0x1",
        KEYRING_AUTH_CLIENTS_JSON:
          '[{"clientId":"a","hmacSecret":"not-a-real-hmac-secret-change-me-0001","allowedKeyIds":["ops"]}]',
      }),
    ).toThrow(/unknown keyId/i);
  });
});
