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

const EnvSchema = z.object({
  PORT: z.coerce.number().int().positive().default(8545),
  HOST: z.string().default("127.0.0.1"),
  LOG_LEVEL: z.enum(["debug", "info", "warn", "error"]).default("info"),
  KEYRING_HMAC_SECRET: z.string().min(16),
  KEYRING_MAX_SKEW_MS: z.coerce.number().int().positive().default(30000),
  KEYRING_NONCE_TTL_MS: z.coerce.number().int().positive().default(120000),
  KEYRING_MAX_VALIDITY_WINDOW_SEC: z.coerce.number().int().positive().default(86400),
  KEYRING_ALLOWED_CHAIN_IDS: z.string().default("").transform(parseChainIds),
  SESSION_PRIVATE_KEY: z.string().startsWith("0x"),
  SESSION_PUBLIC_KEY: z.string().startsWith("0x").optional(),
});

export type AppConfig = z.infer<typeof EnvSchema>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  return EnvSchema.parse(env);
}
