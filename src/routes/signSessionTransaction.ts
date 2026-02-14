import { Router } from "express";
import { ZodError } from "zod";
import { SignSessionTransactionRequestSchema } from "../types/api.js";
import type { SessionTransactionSigner } from "../signer/sessionSigner.js";
import { PolicyError } from "../signer/policy.js";
import type { RequestWithContext } from "../types/http.js";
import type { AuditLogger } from "../audit/logger.js";
import type { LeakScanner } from "../security/leakScanner.js";
import type { RateLimiter } from "../security/rateLimiter.js";

export function signSessionRouter(args: {
  signer: SessionTransactionSigner;
  logger: AuditLogger;
  leakScanner: LeakScanner;
  rateLimiter: RateLimiter | null;
}): Router {
  const router = Router();

  router.post("/v1/sign/session-transaction", async (req: RequestWithContext, res) => {
    try {
      const parsed = SignSessionTransactionRequestSchema.parse(req.body);
      const clientId = req.authContext?.clientId ?? "unknown";

      const inboundScan = args.leakScanner.scan(
        "inbound",
        req.rawBody ?? JSON.stringify(parsed),
        req.requestId,
      );
      if (inboundScan.blocked) {
        res.status(422).json({
          error: "secret leak pattern detected in request payload",
          patterns: inboundScan.patternIds,
        });
        return;
      }

      if (args.rateLimiter) {
        // Rate-limit key is client + account + keyId only.
        // context.tool is NOT included: a caller could evade limits by varying
        // the tool label on each request, splitting traffic across buckets.
        const rateKey = [
          clientId,
          parsed.accountAddress.toLowerCase(),
          parsed.keyId ?? args.signer.defaultKeyId,
        ].join(":");
        const nowMs = Date.now();
        const decision = await args.rateLimiter.check(rateKey, nowMs);
        if (!decision.allowed) {
          args.logger.log({
            level: "warn",
            event: "rate_limit.blocked",
            requestId: req.requestId,
            details: {
              clientId,
              accountAddress: parsed.accountAddress,
              keyId: parsed.keyId ?? args.signer.defaultKeyId,
              tool: parsed.context?.tool,
              resetAtMs: decision.resetAtMs,
            },
          });
          res.setHeader("x-ratelimit-remaining", String(decision.remaining));
          res.setHeader("x-ratelimit-reset-ms", String(decision.resetAtMs));
          res.status(429).json({
            error: "rate limit exceeded",
            retryAfterMs: Math.max(0, decision.resetAtMs - nowMs),
          });
          return;
        }
        res.setHeader("x-ratelimit-remaining", String(decision.remaining));
        res.setHeader("x-ratelimit-reset-ms", String(decision.resetAtMs));
      }

      const result = args.signer.sign(parsed, clientId);

      args.logger.log({
        level: "info",
        event: "sign.session_transaction.success",
        requestId: req.requestId,
        details: {
          accountAddress: parsed.accountAddress,
          keyId: parsed.keyId,
          calls: parsed.calls.length,
          validUntil: parsed.validUntil,
          requester: parsed.context?.requester,
          tool: parsed.context?.tool,
          clientId,
        },
      });

      const responsePayload = {
        requestId: req.requestId,
        messageHash: result.messageHash,
        sessionPublicKey: result.sessionPublicKey,
        signature: result.signature,
      };
      const outboundScan = args.leakScanner.scan(
        "outbound",
        JSON.stringify(responsePayload),
        req.requestId,
      );
      if (outboundScan.blocked) {
        res.status(500).json({ error: "outbound leak scanner blocked response" });
        return;
      }

      res.status(200).json(responsePayload);
    } catch (err) {
      if (err instanceof ZodError) {
        res.status(400).json({ error: "invalid payload", details: err.flatten() });
        return;
      }

      if (err instanceof PolicyError) {
        args.logger.log({
          level: "warn",
          event: "sign.session_transaction.policy_denied",
          requestId: req.requestId,
          details: { reason: err.message },
        });
        res.status(422).json({ error: err.message });
        return;
      }

      args.logger.log({
        level: "error",
        event: "sign.session_transaction.error",
        requestId: req.requestId,
        details: {
          error: err instanceof Error ? err.message : String(err),
        },
      });

      res.status(500).json({ error: "internal error" });
    }
  });

  return router;
}
