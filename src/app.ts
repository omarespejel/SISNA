import express from "express";
import { randomUUID } from "node:crypto";
import type { AppConfig } from "./config.js";
import { AuditLogger } from "./audit/logger.js";
import { InMemoryNonceStore } from "./auth/nonceStore.js";
import { createHmacMiddleware } from "./auth/middleware.js";
import { SessionTransactionSigner } from "./signer/sessionSigner.js";
import { healthRouter } from "./routes/health.js";
import { signSessionRouter } from "./routes/signSessionTransaction.js";
import type { RequestWithContext } from "./types/http.js";

function normalizeFelt(value: string): string {
  return `0x${BigInt(value).toString(16)}`.toLowerCase();
}

export function createApp(config: AppConfig) {
  const app = express();
  const logger = new AuditLogger(config.LOG_LEVEL);
  const nonceStore = new InMemoryNonceStore(config.KEYRING_NONCE_TTL_MS);
  const allowedChainIds = new Set(config.KEYRING_ALLOWED_CHAIN_IDS.map(normalizeFelt));
  const signer = new SessionTransactionSigner(
    config.SIGNING_KEYS,
    config.KEYRING_DEFAULT_KEY_ID,
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
      secret: config.KEYRING_HMAC_SECRET,
      maxSkewMs: config.KEYRING_MAX_SKEW_MS,
      nonceStore,
      logger,
    }),
  );

  app.use(signSessionRouter({ signer, logger }));

  return app;
}
