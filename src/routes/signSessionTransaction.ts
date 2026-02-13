import { Router } from "express";
import { ZodError } from "zod";
import { SignSessionTransactionRequestSchema } from "../types/api.js";
import type { SessionTransactionSigner } from "../signer/sessionSigner.js";
import { PolicyError } from "../signer/policy.js";
import type { RequestWithContext } from "../types/http.js";
import type { AuditLogger } from "../audit/logger.js";

export function signSessionRouter(args: {
  signer: SessionTransactionSigner;
  logger: AuditLogger;
}): Router {
  const router = Router();

  router.post("/v1/sign/session-transaction", (req: RequestWithContext, res) => {
    try {
      const parsed = SignSessionTransactionRequestSchema.parse(req.body);
      const result = args.signer.sign(parsed);

      args.logger.log({
        level: "info",
        event: "sign.session_transaction.success",
        requestId: req.requestId,
        details: {
          accountAddress: parsed.accountAddress,
          calls: parsed.calls.length,
          validUntil: parsed.validUntil,
          requester: parsed.context?.requester,
          tool: parsed.context?.tool,
        },
      });

      res.status(200).json({
        requestId: req.requestId,
        messageHash: result.messageHash,
        sessionPublicKey: result.sessionPublicKey,
        signature: result.signature,
      });
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
