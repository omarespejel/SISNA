import { z } from "zod";

const EnvSchema = z.object({
  PORT: z.coerce.number().int().positive().default(8545),
  HOST: z.string().default("127.0.0.1"),
  LOG_LEVEL: z.enum(["debug", "info", "warn", "error"]).default("info"),
  KEYRING_HMAC_SECRET: z.string().min(16),
  KEYRING_MAX_SKEW_MS: z.coerce.number().int().positive().default(30000),
  KEYRING_NONCE_TTL_MS: z.coerce.number().int().positive().default(120000),
  SESSION_PRIVATE_KEY: z.string().startsWith("0x"),
  SESSION_PUBLIC_KEY: z.string().startsWith("0x").optional(),
});

export type AppConfig = z.infer<typeof EnvSchema>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  return EnvSchema.parse(env);
}
