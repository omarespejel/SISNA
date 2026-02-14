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
import { LeakScanner } from "./security/leakScanner.js";
import { InMemoryRateLimiter, type RateLimiter } from "./security/rateLimiter.js";
import { RedisRateLimiter } from "./security/redisRateLimiter.js";
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

function createRateLimiter(config: AppConfig, logger: AuditLogger): RateLimiter | null {
  if (!config.KEYRING_RATE_LIMIT_ENABLED) {
    logger.log({
      level: "info",
      event: "rate_limit.disabled",
    });
    return null;
  }

  if (config.KEYRING_RATE_LIMIT_BACKEND === "redis") {
    const redis = new Redis(config.KEYRING_REDIS_URL!, {
      lazyConnect: false,
      enableOfflineQueue: false,
      maxRetriesPerRequest: 1,
    });
    redis.on("error", (err: Error) => {
      logger.log({
        level: "error",
        event: "rate_limit.redis_error",
        details: { error: err.message },
      });
    });
    logger.log({
      level: "info",
      event: "rate_limit.enabled",
      details: {
        backend: "redis",
        maxRequests: config.KEYRING_RATE_LIMIT_MAX_REQUESTS,
        windowMs: config.KEYRING_RATE_LIMIT_WINDOW_MS,
      },
    });
    return new RedisRateLimiter(
      redis,
      config.KEYRING_RATE_LIMIT_WINDOW_MS,
      config.KEYRING_RATE_LIMIT_MAX_REQUESTS,
      config.KEYRING_REDIS_RATE_LIMIT_PREFIX,
    );
  }

  logger.log({
    level: "info",
    event: "rate_limit.enabled",
    details: {
      backend: "memory",
      maxRequests: config.KEYRING_RATE_LIMIT_MAX_REQUESTS,
      windowMs: config.KEYRING_RATE_LIMIT_WINDOW_MS,
    },
  });
  return new InMemoryRateLimiter(
    config.KEYRING_RATE_LIMIT_WINDOW_MS,
    config.KEYRING_RATE_LIMIT_MAX_REQUESTS,
  );
}

export function createApp(config: AppConfig) {
  const app = express();
  const logger = new AuditLogger(config.LOG_LEVEL);
  const nonceStore = createNonceStore(config, logger);
  const rateLimiter = createRateLimiter(config, logger);
  const leakScanner = new LeakScanner(
    config.KEYRING_LEAK_SCANNER_ENABLED,
    config.KEYRING_LEAK_SCANNER_ACTION,
    logger,
  );
  const clientSecrets = new Map(config.AUTH_CLIENTS.map((client) => [client.clientId, client.hmacSecret]));
  const allowedKeyIdsByClient = new Map(
    config.AUTH_CLIENTS.map((client) => [
      client.clientId,
      client.allowedKeyIds ? new Set(client.allowedKeyIds) : undefined,
    ]),
  );
  const allowedAccountsByClient = new Map(
    config.AUTH_CLIENTS.map((client) => [
      client.clientId,
      client.allowedAccountAddresses
        ? new Set(client.allowedAccountAddresses.map(normalizeFelt))
        : undefined,
    ]),
  );
  const allowedChainIds = new Set(config.KEYRING_ALLOWED_CHAIN_IDS.map(normalizeFelt));
  const signer = new SessionTransactionSigner(
    config.SIGNING_KEYS,
    config.KEYRING_DEFAULT_KEY_ID,
    allowedKeyIdsByClient,
    allowedAccountsByClient,
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
    req.requestId = randomUUID();
    const callerRequestId = req.header("x-request-id");
    if (callerRequestId) {
      res.setHeader("x-caller-request-id", callerRequestId);
    }
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

  app.use(signSessionRouter({ signer, logger, leakScanner, rateLimiter }));

  return app;
}
