import { loadConfig } from "./config.js";
import { createApp } from "./app.js";
import { createKeyringServer } from "./transport/server.js";

const config = loadConfig();
const app = createApp(config);
const server = createKeyringServer(app, config);
server.requestTimeout = 30_000;
server.headersTimeout = 35_000;
server.keepAliveTimeout = 5_000;

server.listen(config.PORT, config.HOST, () => {
  process.stdout.write(
    `${JSON.stringify({
      ts: new Date().toISOString(),
      level: "info",
      event: "server.started",
      details: {
        host: config.HOST,
        port: config.PORT,
        transport: config.KEYRING_TRANSPORT,
        mtlsRequired: config.KEYRING_MTLS_REQUIRED,
      },
    })}\n`,
  );
});
