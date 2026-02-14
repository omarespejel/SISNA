import type { NextFunction, Response } from "express";
import { buildSigningPayload, computeHmacHex, secureHexEqual } from "./hmac.js";
import type { NonceStore } from "./nonceStore.js";
import type { RequestWithContext } from "../types/http.js";
import type { AuditLogger } from "../audit/logger.js";

const TS_HEADER = "x-keyring-timestamp";
const NONCE_HEADER = "x-keyring-nonce";
const SIG_HEADER = "x-keyring-signature";
const CLIENT_HEADER = "x-keyring-client-id";
const MAX_TIMESTAMP_HEADER_LEN = 32;
const MAX_NONCE_HEADER_LEN = 128;
const MAX_SIGNATURE_HEADER_LEN = 256;
const MAX_CLIENT_ID_HEADER_LEN = 128;

export function createHmacMiddleware(args: {
  defaultClientId: string;
  clientSecrets: Map<string, string>;
  maxSkewMs: number;
  nonceStore: NonceStore;
  logger: AuditLogger;
}) {
  return async function hmacMiddleware(req: RequestWithContext, res: Response, next: NextFunction): Promise<void> {
    const tsRaw = req.header(TS_HEADER);
    const nonce = req.header(NONCE_HEADER);
    const sig = req.header(SIG_HEADER);
    const clientId = req.header(CLIENT_HEADER) ?? args.defaultClientId;

    if (!tsRaw || !nonce || !sig) {
      args.logger.log({
        level: "warn",
        event: "auth.missing_headers",
        requestId: req.requestId,
      });
      res.status(401).json({ error: "missing authentication headers" });
      return;
    }

    if (
      tsRaw.length > MAX_TIMESTAMP_HEADER_LEN
      || nonce.length > MAX_NONCE_HEADER_LEN
      || sig.length > MAX_SIGNATURE_HEADER_LEN
      || clientId.length > MAX_CLIENT_ID_HEADER_LEN
    ) {
      args.logger.log({
        level: "warn",
        event: "auth.header_too_large",
        requestId: req.requestId,
        details: {
          timestampLen: tsRaw.length,
          nonceLen: nonce.length,
          signatureLen: sig.length,
          clientIdLen: clientId.length,
        },
      });
      res.status(401).json({ error: "authentication header too large" });
      return;
    }

    const secret = args.clientSecrets.get(clientId);
    if (!secret) {
      args.logger.log({
        level: "warn",
        event: "auth.unknown_client",
        requestId: req.requestId,
        details: { clientId },
      });
      res.status(401).json({ error: "unknown client id" });
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

    const rawBody = req.rawBody ?? "";
    const payload = buildSigningPayload({
      timestamp: tsRaw,
      nonce,
      method: req.method,
      path: req.originalUrl,
      rawBody,
    });
    const expected = computeHmacHex(secret, payload);

    if (!secureHexEqual(sig, expected)) {
      args.logger.log({
        level: "warn",
        event: "auth.invalid_signature",
        requestId: req.requestId,
      });
      res.status(401).json({ error: "invalid signature" });
      return;
    }

    try {
      const nonceAccepted = await args.nonceStore.consume(nonce, now);
      if (!nonceAccepted) {
        args.logger.log({
          level: "warn",
          event: "auth.replay_nonce",
          requestId: req.requestId,
          details: { nonce },
        });
        res.status(401).json({ error: "replayed nonce" });
        return;
      }
    } catch (err) {
      args.logger.log({
        level: "error",
        event: "auth.replay_store_unavailable",
        requestId: req.requestId,
        details: {
          error: err instanceof Error ? err.message : String(err),
        },
      });
      res.status(503).json({ error: "replay protection unavailable" });
      return;
    }

    req.authContext = { nonce, timestamp: ts, clientId };
    next();
  };
}
