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

const SigningKeySchema = z.object({
  keyId: z.string().min(1),
  privateKey: z.string().startsWith("0x"),
  publicKey: z.string().startsWith("0x").optional(),
});

const EnvSchema = z.object({
  PORT: z.coerce.number().int().positive().default(8545),
  HOST: z.string().default("127.0.0.1"),
  LOG_LEVEL: z.enum(["debug", "info", "warn", "error"]).default("info"),
  KEYRING_HMAC_SECRET: z.string().min(16),
  KEYRING_MAX_SKEW_MS: z.coerce.number().int().positive().default(30000),
  KEYRING_NONCE_TTL_MS: z.coerce.number().int().positive().default(120000),
  KEYRING_MAX_VALIDITY_WINDOW_SEC: z.coerce.number().int().positive().default(86400),
  KEYRING_ALLOWED_CHAIN_IDS: z.string().default("").transform(parseChainIds),
  KEYRING_REPLAY_STORE: z.enum(["memory", "redis"]).default("memory"),
  KEYRING_REDIS_URL: z.string().url().optional(),
  KEYRING_REDIS_NONCE_PREFIX: z.string().default("starknet-keyring-proxy:nonce:"),
  KEYRING_DEFAULT_KEY_ID: z.string().min(1).default("default"),
  KEYRING_SIGNING_KEYS_JSON: z.string().default(""),
  SESSION_PRIVATE_KEY: z.string().startsWith("0x").optional(),
  SESSION_PUBLIC_KEY: z.string().startsWith("0x").optional(),
});

export type SigningKeyConfig = z.infer<typeof SigningKeySchema>;

export type AppConfig = {
  PORT: number;
  HOST: string;
  LOG_LEVEL: "debug" | "info" | "warn" | "error";
  KEYRING_HMAC_SECRET: string;
  KEYRING_MAX_SKEW_MS: number;
  KEYRING_NONCE_TTL_MS: number;
  KEYRING_MAX_VALIDITY_WINDOW_SEC: number;
  KEYRING_ALLOWED_CHAIN_IDS: string[];
  KEYRING_REPLAY_STORE: "memory" | "redis";
  KEYRING_REDIS_URL?: string;
  KEYRING_REDIS_NONCE_PREFIX: string;
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

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const parsed = EnvSchema.parse(env);
  const fromJson = parseSigningKeysJson(parsed.KEYRING_SIGNING_KEYS_JSON);

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

  if (parsed.KEYRING_REPLAY_STORE === "redis" && !parsed.KEYRING_REDIS_URL) {
    throw new Error("KEYRING_REDIS_URL is required when KEYRING_REPLAY_STORE=redis");
  }

  return {
    PORT: parsed.PORT,
    HOST: parsed.HOST,
    LOG_LEVEL: parsed.LOG_LEVEL,
    KEYRING_HMAC_SECRET: parsed.KEYRING_HMAC_SECRET,
    KEYRING_MAX_SKEW_MS: parsed.KEYRING_MAX_SKEW_MS,
    KEYRING_NONCE_TTL_MS: parsed.KEYRING_NONCE_TTL_MS,
    KEYRING_MAX_VALIDITY_WINDOW_SEC: parsed.KEYRING_MAX_VALIDITY_WINDOW_SEC,
    KEYRING_ALLOWED_CHAIN_IDS: parsed.KEYRING_ALLOWED_CHAIN_IDS,
    KEYRING_REPLAY_STORE: parsed.KEYRING_REPLAY_STORE,
    KEYRING_REDIS_URL: parsed.KEYRING_REDIS_URL,
    KEYRING_REDIS_NONCE_PREFIX: parsed.KEYRING_REDIS_NONCE_PREFIX,
    KEYRING_DEFAULT_KEY_ID: parsed.KEYRING_DEFAULT_KEY_ID,
    SIGNING_KEYS: signingKeys,
  };
}
