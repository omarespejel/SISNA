import type { NextFunction, Response } from "express";
import { buildSigningPayload, computeHmacHex, secureHexEqual } from "./hmac.js";
import type { NonceStore } from "./nonceStore.js";
import type { RequestWithContext } from "../types/http.js";
import type { AuditLogger } from "../audit/logger.js";

const TS_HEADER = "x-keyring-timestamp";
const NONCE_HEADER = "x-keyring-nonce";
const SIG_HEADER = "x-keyring-signature";

export function createHmacMiddleware(args: {
  secret: string;
  maxSkewMs: number;
  nonceStore: NonceStore;
  logger: AuditLogger;
}) {
  return function hmacMiddleware(req: RequestWithContext, res: Response, next: NextFunction): void {
    const tsRaw = req.header(TS_HEADER);
    const nonce = req.header(NONCE_HEADER);
    const sig = req.header(SIG_HEADER);

    if (!tsRaw || !nonce || !sig) {
      args.logger.log({
        level: "warn",
        event: "auth.missing_headers",
        requestId: req.requestId,
      });
      res.status(401).json({ error: "missing authentication headers" });
      return;
    }

    const ts = Number(tsRaw);
    if (!Number.isFinite(ts)) {
      res.status(401).json({ error: "invalid timestamp" });
      return;
    }

    const now = Date.now();
    if (Math.abs(now - ts) > args.maxSkewMs) {
      args.logger.log({
        level: "warn",
        event: "auth.timestamp_out_of_window",
        requestId: req.requestId,
        details: { now, ts, maxSkewMs: args.maxSkewMs },
      });
      res.status(401).json({ error: "timestamp outside accepted window" });
      return;
    }

    if (!args.nonceStore.consume(nonce, now)) {
      args.logger.log({
        level: "warn",
        event: "auth.replay_nonce",
        requestId: req.requestId,
        details: { nonce },
      });
      res.status(401).json({ error: "replayed nonce" });
      return;
    }

    const rawBody = req.rawBody ?? "";
    const payload = buildSigningPayload({
      timestamp: tsRaw,
      nonce,
      method: req.method,
      path: req.path,
      rawBody,
    });
    const expected = computeHmacHex(args.secret, payload);

    if (!secureHexEqual(sig, expected)) {
      args.logger.log({
        level: "warn",
        event: "auth.invalid_signature",
        requestId: req.requestId,
      });
      res.status(401).json({ error: "invalid signature" });
      return;
    }

    req.authContext = { nonce, timestamp: ts };
    next();
  };
}
