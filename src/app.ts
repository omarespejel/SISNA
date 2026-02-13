import express from "express";
import { randomUUID } from "node:crypto";
import { Redis } from "ioredis";
import type { AppConfig } from "./config.js";
import { AuditLogger } from "./audit/logger.js";
import { InMemoryNonceStore } from "./auth/nonceStore.js";
import type { NonceStore } from "./auth/nonceStore.js";
import { RedisNonceStore } from "./auth/redisNonceStore.js";
import { createHmacMiddleware } from "./auth/middleware.js";
import { SessionTransactionSigner } from "./signer/sessionSigner.js";
import { healthRouter } from "./routes/health.js";
import { signSessionRouter } from "./routes/signSessionTransaction.js";
import type { RequestWithContext } from "./types/http.js";

function normalizeFelt(value: string): string {
  return `0x${BigInt(value).toString(16)}`.toLowerCase();
}

function createNonceStore(config: AppConfig, logger: AuditLogger): NonceStore {
  if (config.KEYRING_REPLAY_STORE === "redis") {
    const redis = new Redis(config.KEYRING_REDIS_URL!, {
      lazyConnect: false,
      enableOfflineQueue: false,
      maxRetriesPerRequest: 1,
    });
    redis.on("error", (err: Error) => {
      logger.log({
        level: "error",
        event: "replay.redis_error",
        details: { error: err.message },
      });
    });
    logger.log({
      level: "info",
      event: "replay.store_selected",
      details: { store: "redis", nonceTtlMs: config.KEYRING_NONCE_TTL_MS },
    });
    return new RedisNonceStore(redis, config.KEYRING_NONCE_TTL_MS, config.KEYRING_REDIS_NONCE_PREFIX);
  }

  logger.log({
    level: "info",
    event: "replay.store_selected",
    details: { store: "memory", nonceTtlMs: config.KEYRING_NONCE_TTL_MS },
  });
  return new InMemoryNonceStore(config.KEYRING_NONCE_TTL_MS);
}

export function createApp(config: AppConfig) {
  const app = express();
  const logger = new AuditLogger(config.LOG_LEVEL);
  const nonceStore = createNonceStore(config, logger);
  const clientSecrets = new Map(config.AUTH_CLIENTS.map((client) => [client.clientId, client.hmacSecret]));
  const allowedKeyIdsByClient = new Map(
    config.AUTH_CLIENTS.map((client) => [
      client.clientId,
      client.allowedKeyIds ? new Set(client.allowedKeyIds) : undefined,
    ]),
  );
  const allowedChainIds = new Set(config.KEYRING_ALLOWED_CHAIN_IDS.map(normalizeFelt));
  const signer = new SessionTransactionSigner(
    config.SIGNING_KEYS,
    config.KEYRING_DEFAULT_KEY_ID,
    allowedKeyIdsByClient,
    {
      maxValidityWindowSec: config.KEYRING_MAX_VALIDITY_WINDOW_SEC,
      allowedChainIds,
    },
  );

  app.use(
    express.json({
      verify: (req, _res, buf) => {
        (req as RequestWithContext).rawBody = buf.toString("utf8");
      },
    }),
  );

  app.use((req: RequestWithContext, res, next) => {
    req.requestId = req.header("x-request-id") ?? randomUUID();
    res.setHeader("x-request-id", req.requestId);
    next();
  });

  app.use(healthRouter());

  app.use(
    createHmacMiddleware({
      defaultClientId: config.KEYRING_DEFAULT_AUTH_CLIENT_ID,
      clientSecrets,
      maxSkewMs: config.KEYRING_MAX_SKEW_MS,
      nonceStore,
      logger,
    }),
  );

  app.use(signSessionRouter({ signer, logger }));

  return app;
}
