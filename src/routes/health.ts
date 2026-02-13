import { Router } from "express";

export function healthRouter(): Router {
  const router = Router();

  router.get("/health", (_req, res) => {
    res.status(200).json({ ok: true, service: "starknet-keyring-proxy" });
  });

  return router;
}
