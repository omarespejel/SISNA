import fs from "node:fs";
import http from "node:http";
import https, { type ServerOptions as HttpsServerOptions } from "node:https";
import type { Express } from "express";
import type { AppConfig } from "../config.js";

export function buildHttpsServerOptions(
  config: AppConfig,
  readFileSync: (path: string) => Buffer = fs.readFileSync,
): HttpsServerOptions {
  if (config.KEYRING_TRANSPORT !== "https") {
    throw new Error("HTTPS options requested while KEYRING_TRANSPORT is not https");
  }
  if (!config.KEYRING_TLS_CERT_PATH || !config.KEYRING_TLS_KEY_PATH) {
    throw new Error("TLS certificate and key paths are required for https transport");
  }

  return {
    key: readFileSync(config.KEYRING_TLS_KEY_PATH),
    cert: readFileSync(config.KEYRING_TLS_CERT_PATH),
    ca: config.KEYRING_TLS_CA_PATH ? readFileSync(config.KEYRING_TLS_CA_PATH) : undefined,
    requestCert: config.KEYRING_MTLS_REQUIRED,
    rejectUnauthorized: config.KEYRING_MTLS_REQUIRED,
    minVersion: "TLSv1.2",
  };
}

export function createKeyringServer(app: Express, config: AppConfig): http.Server | https.Server {
  if (config.KEYRING_TRANSPORT === "https") {
    return https.createServer(buildHttpsServerOptions(config), app);
  }

  return http.createServer(app);
}

