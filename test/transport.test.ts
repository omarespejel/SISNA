import { describe, expect, it, vi } from "vitest";
import { buildHttpsServerOptions } from "../src/transport/server.js";
import type { AppConfig } from "../src/config.js";

const baseConfig: AppConfig = {
  NODE_ENV: "test",
  PORT: 8545,
  HOST: "127.0.0.1",
  KEYRING_TRANSPORT: "https",
  KEYRING_TLS_CERT_PATH: "/tmp/server.crt",
  KEYRING_TLS_KEY_PATH: "/tmp/server.key",
  KEYRING_TLS_CA_PATH: "/tmp/ca.crt",
  KEYRING_MTLS_REQUIRED: true,
  LOG_LEVEL: "error",
  KEYRING_HMAC_SECRET: "0123456789abcdef0123456789abcdef",
  KEYRING_MAX_SKEW_MS: 60_000,
  KEYRING_NONCE_TTL_MS: 120_000,
  KEYRING_MAX_VALIDITY_WINDOW_SEC: 24 * 60 * 60,
  KEYRING_ALLOWED_CHAIN_IDS: [],
  KEYRING_REPLAY_STORE: "memory",
  KEYRING_REDIS_NONCE_PREFIX: "starknet-keyring-proxy:nonce:",
  KEYRING_DEFAULT_KEY_ID: "default",
  SIGNING_KEYS: [{ keyId: "default", privateKey: "0x1", publicKey: undefined }],
};

describe("transport tls", () => {
  it("builds https options and enables mTLS when required", () => {
    const readFile = vi.fn((path: string) => Buffer.from(`file:${path}`));
    const opts = buildHttpsServerOptions(baseConfig, readFile);

    expect(opts.requestCert).toBe(true);
    expect(opts.rejectUnauthorized).toBe(true);
    expect(readFile).toHaveBeenCalledWith("/tmp/server.key");
    expect(readFile).toHaveBeenCalledWith("/tmp/server.crt");
    expect(readFile).toHaveBeenCalledWith("/tmp/ca.crt");
  });

  it("supports https without mTLS", () => {
    const readFile = vi.fn((path: string) => Buffer.from(`file:${path}`));
    const opts = buildHttpsServerOptions(
      {
        ...baseConfig,
        KEYRING_MTLS_REQUIRED: false,
        KEYRING_TLS_CA_PATH: undefined,
      },
      readFile,
    );

    expect(opts.requestCert).toBe(false);
    expect(opts.rejectUnauthorized).toBe(false);
    expect(readFile).toHaveBeenCalledTimes(2);
  });
});
