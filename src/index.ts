import { loadConfig } from "./config.js";
import { createApp } from "./app.js";
import { createKeyringServer } from "./transport/server.js";
import { AuditLogger } from "./audit/logger.js";

const config = loadConfig();
const app = createApp(config);
const server = createKeyringServer(app, config);
const logger = new AuditLogger(config.LOG_LEVEL);
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
