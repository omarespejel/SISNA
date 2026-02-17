import { loadConfig } from "./config.js";
import { createApp } from "./app.js";
import { createKeyringServer } from "./transport/server.js";
import { AuditLogger } from "./audit/logger.js";
import { runDfnsPreflightCheck } from "./signer/provider.js";

async function main() {
  const config = loadConfig();
  const logger = new AuditLogger(config.LOG_LEVEL);

  if (
    config.KEYRING_SIGNER_PROVIDER === "dfns"
    && config.KEYRING_DFNS_PREFLIGHT_ON_STARTUP
  ) {
    const preflightResult = await runDfnsPreflightCheck({
      endpointUrl: config.KEYRING_DFNS_SIGNER_URL!,
      timeoutMs: config.KEYRING_DFNS_PREFLIGHT_TIMEOUT_MS,
      authToken: config.KEYRING_DFNS_AUTH_TOKEN!,
      userActionSignature: config.KEYRING_DFNS_USER_ACTION_SIGNATURE!,
    });
    if (!preflightResult.ok) {
      logger.log({
        level: "error",
        event: "dfns.preflight.startup_failed",
        details: preflightResult,
      });
      throw new Error(preflightResult.error ?? "DFNS preflight failed");
    }
    logger.log({
      level: "info",
      event: "dfns.preflight.startup_ok",
      details: preflightResult,
    });
  }

  const app = createApp(config);
  const server = createKeyringServer(app, config);
  server.requestTimeout = 30_000;
  server.headersTimeout = 35_000;
  server.keepAliveTimeout = 5_000;

  server.listen(config.PORT, config.HOST, () => {
    logger.log({
      level: "info",
      event: "server.started",
      details: {
        host: config.HOST,
        port: config.PORT,
        transport: config.KEYRING_TRANSPORT,
        mtlsRequired: config.KEYRING_MTLS_REQUIRED,
      },
    });
  });
}

void main().catch((err) => {
  // Startup failures happen before request handling is available.
  // Keep this explicit and fail-closed.
  // eslint-disable-next-line no-console
  console.error(
    `[startup] ${err instanceof Error ? err.message : String(err)}`,
  );
  process.exit(1);
});
