import { loadConfig } from "./config.js";
import { createApp } from "./app.js";

const config = loadConfig();
const app = createApp(config);

app.listen(config.PORT, config.HOST, () => {
  process.stdout.write(
    `${JSON.stringify({
      ts: new Date().toISOString(),
      level: "info",
      event: "server.started",
      details: {
        host: config.HOST,
        port: config.PORT,
      },
    })}\n`,
  );
});
