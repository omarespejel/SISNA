import { z } from "zod";

function parseChainIds(raw: string | undefined): string[] {
  if (!raw) {
    return [];
  }
  return raw
    .split(",")
    .map((value) => value.trim())
    .filter((value) => value.length > 0);
}

function parseBoolean(raw: string | undefined): boolean {
  if (!raw) {
    return false;
  }
  const value = raw.trim().toLowerCase();
  return value === "1" || value === "true" || value === "yes" || value === "on";
}

const SigningKeySchema = z.object({
  keyId: z.string().min(1),
  privateKey: z.string().startsWith("0x"),
  publicKey: z.string().startsWith("0x").optional(),
});

const AuthClientSchema = z.object({
  clientId: z.string().min(1),
  hmacSecret: z.string().min(16),
  allowedKeyIds: z.array(z.string().min(1)).optional(),
  allowedAccountAddresses: z.array(z.string().startsWith("0x")).optional(),
});

const EnvSchema = z.object({
  NODE_ENV: z.string().optional(),
  PORT: z.coerce.number().int().positive().default(8545),
  HOST: z.string().default("127.0.0.1"),
  KEYRING_TRANSPORT: z.enum(["http", "https"]).default("http"),
  KEYRING_TLS_CERT_PATH: z.string().optional(),
  KEYRING_TLS_KEY_PATH: z.string().optional(),
  KEYRING_TLS_CA_PATH: z.string().optional(),
  KEYRING_MTLS_REQUIRED: z.string().default("false").transform(parseBoolean),
  LOG_LEVEL: z.enum(["debug", "info", "warn", "error"]).default("info"),
  KEYRING_HMAC_SECRET: z.string().min(16).optional(),
  KEYRING_DEFAULT_AUTH_CLIENT_ID: z.string().min(1).default("default"),
  KEYRING_AUTH_CLIENTS_JSON: z.string().default(""),
  KEYRING_MAX_SKEW_MS: z.coerce.number().int().positive().default(30000),
  KEYRING_NONCE_TTL_MS: z.coerce.number().int().positive().default(120000),
  KEYRING_MAX_VALIDITY_WINDOW_SEC: z.coerce.number().int().positive().default(86400),
  KEYRING_ALLOWED_CHAIN_IDS: z.string().default("").transform(parseChainIds),
  KEYRING_REPLAY_STORE: z.enum(["memory", "redis"]).default("memory"),
  KEYRING_REDIS_URL: z.string().url().optional(),
  KEYRING_REDIS_NONCE_PREFIX: z.string().default("starknet-keyring-proxy:nonce:"),
  KEYRING_RATE_LIMIT_ENABLED: z.string().default("false").transform(parseBoolean),
  KEYRING_RATE_LIMIT_BACKEND: z.enum(["memory", "redis"]).default("memory"),
  KEYRING_RATE_LIMIT_WINDOW_MS: z.coerce.number().int().positive().default(60_000),
  KEYRING_RATE_LIMIT_MAX_REQUESTS: z.coerce.number().int().positive().default(120),
  KEYRING_REDIS_RATE_LIMIT_PREFIX: z.string().default("starknet-keyring-proxy:ratelimit:"),
  KEYRING_LEAK_SCANNER_ENABLED: z.string().default("false").transform(parseBoolean),
  KEYRING_LEAK_SCANNER_ACTION: z.enum(["block", "warn"]).default("block"),
  KEYRING_ALLOW_INSECURE_IN_PROCESS_KEYS_IN_PRODUCTION: z
    .string()
    .default("false")
    .transform(parseBoolean),
  KEYRING_DEFAULT_KEY_ID: z.string().min(1).default("default"),
  KEYRING_SIGNING_KEYS_JSON: z.string().default(""),
  SESSION_PRIVATE_KEY: z.string().startsWith("0x").optional(),
  SESSION_PUBLIC_KEY: z.string().startsWith("0x").optional(),
});

export type SigningKeyConfig = z.infer<typeof SigningKeySchema>;
export type AuthClientConfig = z.infer<typeof AuthClientSchema>;

export type AppConfig = {
  NODE_ENV: string;
  PORT: number;
  HOST: string;
  KEYRING_TRANSPORT: "http" | "https";
  KEYRING_TLS_CERT_PATH?: string;
  KEYRING_TLS_KEY_PATH?: string;
  KEYRING_TLS_CA_PATH?: string;
  KEYRING_MTLS_REQUIRED: boolean;
  LOG_LEVEL: "debug" | "info" | "warn" | "error";
  KEYRING_DEFAULT_AUTH_CLIENT_ID: string;
  AUTH_CLIENTS: AuthClientConfig[];
  KEYRING_MAX_SKEW_MS: number;
  KEYRING_NONCE_TTL_MS: number;
  KEYRING_MAX_VALIDITY_WINDOW_SEC: number;
  KEYRING_ALLOWED_CHAIN_IDS: string[];
  KEYRING_REPLAY_STORE: "memory" | "redis";
  KEYRING_REDIS_URL?: string;
  KEYRING_REDIS_NONCE_PREFIX: string;
  KEYRING_RATE_LIMIT_ENABLED: boolean;
  KEYRING_RATE_LIMIT_BACKEND: "memory" | "redis";
  KEYRING_RATE_LIMIT_WINDOW_MS: number;
  KEYRING_RATE_LIMIT_MAX_REQUESTS: number;
  KEYRING_REDIS_RATE_LIMIT_PREFIX: string;
  KEYRING_LEAK_SCANNER_ENABLED: boolean;
  KEYRING_LEAK_SCANNER_ACTION: "block" | "warn";
  KEYRING_ALLOW_INSECURE_IN_PROCESS_KEYS_IN_PRODUCTION: boolean;
  KEYRING_DEFAULT_KEY_ID: string;
  SIGNING_KEYS: SigningKeyConfig[];
};

function parseSigningKeysJson(raw: string): SigningKeyConfig[] | undefined {
  if (!raw.trim()) {
    return undefined;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(
      `KEYRING_SIGNING_KEYS_JSON is not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  const asArray = z.array(SigningKeySchema).min(1).parse(parsed);
  return asArray;
}

function parseAuthClientsJson(raw: string): AuthClientConfig[] | undefined {
  if (!raw.trim()) {
    return undefined;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(
      `KEYRING_AUTH_CLIENTS_JSON is not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  return z.array(AuthClientSchema).min(1).parse(parsed);
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const parsed = EnvSchema.parse(env);
  const runtimeEnvironment = (parsed.NODE_ENV ?? "development").toLowerCase();
  const isProduction = runtimeEnvironment === "production";
  const fromJson = parseSigningKeysJson(parsed.KEYRING_SIGNING_KEYS_JSON);
  const authClientsFromJson = parseAuthClientsJson(parsed.KEYRING_AUTH_CLIENTS_JSON);

  const signingKeys = fromJson ?? (
    parsed.SESSION_PRIVATE_KEY
      ? [
          {
            keyId: parsed.KEYRING_DEFAULT_KEY_ID,
            privateKey: parsed.SESSION_PRIVATE_KEY,
            publicKey: parsed.SESSION_PUBLIC_KEY,
          },
        ]
      : undefined
  );

  if (!signingKeys) {
    throw new Error(
      "No signing key configured. Set SESSION_PRIVATE_KEY or KEYRING_SIGNING_KEYS_JSON.",
    );
  }

  const authClients = authClientsFromJson ?? (
    parsed.KEYRING_HMAC_SECRET
      ? [
          {
            clientId: parsed.KEYRING_DEFAULT_AUTH_CLIENT_ID,
            hmacSecret: parsed.KEYRING_HMAC_SECRET,
            allowedKeyIds: undefined,
          },
        ]
      : undefined
  );

  if (!authClients) {
    throw new Error(
      "No auth clients configured. Set KEYRING_HMAC_SECRET or KEYRING_AUTH_CLIENTS_JSON.",
    );
  }

  const keyIds = new Set<string>();
  for (const key of signingKeys) {
    if (keyIds.has(key.keyId)) {
      throw new Error(`Duplicate keyId in signing keys: ${key.keyId}`);
    }
    keyIds.add(key.keyId);
  }
  if (!keyIds.has(parsed.KEYRING_DEFAULT_KEY_ID)) {
    throw new Error(
      `KEYRING_DEFAULT_KEY_ID (${parsed.KEYRING_DEFAULT_KEY_ID}) not present in signing keys`,
    );
  }

  const clientIds = new Set<string>();
  for (const client of authClients) {
    if (clientIds.has(client.clientId)) {
      throw new Error(`Duplicate auth client id: ${client.clientId}`);
    }
    clientIds.add(client.clientId);
    if (client.allowedKeyIds) {
      for (const keyId of client.allowedKeyIds) {
        if (!keyIds.has(keyId)) {
          throw new Error(`Client ${client.clientId} references unknown keyId: ${keyId}`);
        }
      }
    }
  }

  if (!clientIds.has(parsed.KEYRING_DEFAULT_AUTH_CLIENT_ID)) {
    throw new Error(
      `KEYRING_DEFAULT_AUTH_CLIENT_ID (${parsed.KEYRING_DEFAULT_AUTH_CLIENT_ID}) not present in auth clients`,
    );
  }

  if (parsed.KEYRING_REPLAY_STORE === "redis" && !parsed.KEYRING_REDIS_URL) {
    throw new Error("KEYRING_REDIS_URL is required when KEYRING_REPLAY_STORE=redis");
  }
  if (
    parsed.KEYRING_RATE_LIMIT_ENABLED
      && parsed.KEYRING_RATE_LIMIT_BACKEND === "redis"
      && !parsed.KEYRING_REDIS_URL
  ) {
    throw new Error("KEYRING_REDIS_URL is required when KEYRING_RATE_LIMIT_BACKEND=redis");
  }

  if (parsed.KEYRING_TRANSPORT === "https") {
    if (!parsed.KEYRING_TLS_CERT_PATH || !parsed.KEYRING_TLS_KEY_PATH) {
      throw new Error(
        "KEYRING_TLS_CERT_PATH and KEYRING_TLS_KEY_PATH are required when KEYRING_TRANSPORT=https",
      );
    }
  }

  if (parsed.KEYRING_MTLS_REQUIRED) {
    if (parsed.KEYRING_TRANSPORT !== "https") {
      throw new Error("KEYRING_MTLS_REQUIRED=true requires KEYRING_TRANSPORT=https");
    }
    if (!parsed.KEYRING_TLS_CA_PATH) {
      throw new Error("KEYRING_TLS_CA_PATH is required when KEYRING_MTLS_REQUIRED=true");
    }
  }

  if (isProduction) {
    if (parsed.KEYRING_TRANSPORT !== "https") {
      throw new Error("NODE_ENV=production requires KEYRING_TRANSPORT=https");
    }
    if (!parsed.KEYRING_MTLS_REQUIRED) {
      throw new Error("NODE_ENV=production requires KEYRING_MTLS_REQUIRED=true");
    }
    const redisRequired = parsed.KEYRING_REPLAY_STORE === "redis"
      || (parsed.KEYRING_RATE_LIMIT_ENABLED && parsed.KEYRING_RATE_LIMIT_BACKEND === "redis");
    if (redisRequired && parsed.KEYRING_REDIS_URL && !parsed.KEYRING_REDIS_URL.startsWith("rediss://")) {
      throw new Error("NODE_ENV=production requires KEYRING_REDIS_URL to use rediss://");
    }
    if (!parsed.KEYRING_ALLOW_INSECURE_IN_PROCESS_KEYS_IN_PRODUCTION) {
      throw new Error(
        "NODE_ENV=production requires explicit KEYRING_ALLOW_INSECURE_IN_PROCESS_KEYS_IN_PRODUCTION=true until external KMS/HSM signer mode is enabled",
      );
    }
  }

  return {
    NODE_ENV: runtimeEnvironment,
    PORT: parsed.PORT,
    HOST: parsed.HOST,
    KEYRING_TRANSPORT: parsed.KEYRING_TRANSPORT,
    KEYRING_TLS_CERT_PATH: parsed.KEYRING_TLS_CERT_PATH,
    KEYRING_TLS_KEY_PATH: parsed.KEYRING_TLS_KEY_PATH,
    KEYRING_TLS_CA_PATH: parsed.KEYRING_TLS_CA_PATH,
    KEYRING_MTLS_REQUIRED: parsed.KEYRING_MTLS_REQUIRED,
    LOG_LEVEL: parsed.LOG_LEVEL,
    KEYRING_DEFAULT_AUTH_CLIENT_ID: parsed.KEYRING_DEFAULT_AUTH_CLIENT_ID,
    AUTH_CLIENTS: authClients,
    KEYRING_MAX_SKEW_MS: parsed.KEYRING_MAX_SKEW_MS,
    KEYRING_NONCE_TTL_MS: parsed.KEYRING_NONCE_TTL_MS,
    KEYRING_MAX_VALIDITY_WINDOW_SEC: parsed.KEYRING_MAX_VALIDITY_WINDOW_SEC,
    KEYRING_ALLOWED_CHAIN_IDS: parsed.KEYRING_ALLOWED_CHAIN_IDS,
    KEYRING_REPLAY_STORE: parsed.KEYRING_REPLAY_STORE,
    KEYRING_REDIS_URL: parsed.KEYRING_REDIS_URL,
    KEYRING_REDIS_NONCE_PREFIX: parsed.KEYRING_REDIS_NONCE_PREFIX,
    KEYRING_RATE_LIMIT_ENABLED: parsed.KEYRING_RATE_LIMIT_ENABLED,
    KEYRING_RATE_LIMIT_BACKEND: parsed.KEYRING_RATE_LIMIT_BACKEND,
    KEYRING_RATE_LIMIT_WINDOW_MS: parsed.KEYRING_RATE_LIMIT_WINDOW_MS,
    KEYRING_RATE_LIMIT_MAX_REQUESTS: parsed.KEYRING_RATE_LIMIT_MAX_REQUESTS,
    KEYRING_REDIS_RATE_LIMIT_PREFIX: parsed.KEYRING_REDIS_RATE_LIMIT_PREFIX,
    KEYRING_LEAK_SCANNER_ENABLED: parsed.KEYRING_LEAK_SCANNER_ENABLED,
    KEYRING_LEAK_SCANNER_ACTION: parsed.KEYRING_LEAK_SCANNER_ACTION,
    KEYRING_ALLOW_INSECURE_IN_PROCESS_KEYS_IN_PRODUCTION:
      parsed.KEYRING_ALLOW_INSECURE_IN_PROCESS_KEYS_IN_PRODUCTION,
    KEYRING_DEFAULT_KEY_ID: parsed.KEYRING_DEFAULT_KEY_ID,
    SIGNING_KEYS: signingKeys,
  };
}
