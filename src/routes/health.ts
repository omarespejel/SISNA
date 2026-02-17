import { Router } from "express";
import type { AppConfig } from "../config.js";
import { runDfnsPreflightCheck } from "../signer/provider.js";

export function healthRouter(config: AppConfig): Router {
  const router = Router();

  router.get("/health", (_req, res) => {
    res.status(200).json({ ok: true });
  });

  router.get("/health/dfns-preflight", async (_req, res) => {
    if (config.KEYRING_SIGNER_PROVIDER !== "dfns") {
      res.status(404).json({ error: "dfns signer provider is not enabled" });
      return;
    }
    const result = await runDfnsPreflightCheck({
      endpointUrl: config.KEYRING_DFNS_SIGNER_URL!,
      timeoutMs: config.KEYRING_DFNS_PREFLIGHT_TIMEOUT_MS,
      authToken: config.KEYRING_DFNS_AUTH_TOKEN!,
      userActionSignature: config.KEYRING_DFNS_USER_ACTION_SIGNATURE!,
    });
    res.status(result.ok ? 200 : 503).json(result);
  });

  return router;
}
