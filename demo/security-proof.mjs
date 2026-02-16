#!/usr/bin/env node

import { createHash, createHmac, randomUUID } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

function argValue(name, fallback = undefined) {
  const idx = process.argv.indexOf(`--${name}`);
  if (idx === -1 || idx + 1 >= process.argv.length) {
    return fallback;
  }
  return process.argv[idx + 1];
}

function nowIsoCompact() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function sha256Hex(input) {
  return createHash("sha256").update(input).digest("hex");
}

function buildSigningPayload({ timestamp, nonce, method, pathWithQuery, rawBody }) {
  return `${timestamp}.${nonce}.${method.toUpperCase()}.${pathWithQuery}.${sha256Hex(rawBody)}`;
}

function computeHmacHex(secret, payload) {
  return createHmac("sha256", secret).update(payload).digest("hex");
}

function buildHeaders({ url, rawBody, secret, clientId, nonce, timestamp }) {
  const parsed = new URL(url);
  const pathWithQuery = `${parsed.pathname}${parsed.search}`;
  const signingPayload = buildSigningPayload({
    timestamp,
    nonce,
    method: "POST",
    pathWithQuery,
    rawBody,
  });
  const signature = computeHmacHex(secret, signingPayload);
  return {
    "content-type": "application/json",
    "x-keyring-client-id": clientId,
    "x-keyring-timestamp": timestamp,
    "x-keyring-nonce": nonce,
    "x-keyring-signature": signature,
  };
}

async function postSigned({ url, body, secret, clientId, nonce, timestamp }) {
  const rawBody = JSON.stringify(body);
  const headers = buildHeaders({
    url,
    rawBody,
    secret,
    clientId,
    nonce,
    timestamp,
  });
  const response = await fetch(url, {
    method: "POST",
    headers,
    body: rawBody,
  });
  const text = await response.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = { raw: text };
  }
  return {
    status: response.status,
    headers: Object.fromEntries(response.headers.entries()),
    body: parsed,
    request: {
      nonce,
      timestamp,
      payload: body,
      headers,
    },
  };
}

function makeHappyPayload({ accountAddress, chainId, nonceHex, validUntil, contractAddress }) {
  return {
    accountAddress,
    chainId,
    nonce: nonceHex,
    validUntil,
    calls: [
      {
        contractAddress,
        entrypoint: "transfer",
        calldata: ["0xabc", "0x1", "0x0"],
      },
    ],
    context: {
      requester: "security-proof-demo",
      tool: "starknet_transfer",
      reason: "happy-path",
    },
  };
}

function makeDeniedSelectorPayload({ accountAddress, chainId, nonceHex, validUntil, contractAddress }) {
  return {
    accountAddress,
    chainId,
    nonce: nonceHex,
    validUntil,
    calls: [
      {
        contractAddress,
        entrypoint: "set_agent_id",
        calldata: ["0x1"],
      },
    ],
    context: {
      requester: "security-proof-demo",
      tool: "starknet_invoke_contract",
      reason: "policy-deny-test",
    },
  };
}

function assertCase(name, condition, detail) {
  if (!condition) {
    throw new Error(`[${name}] ${detail}`);
  }
}

async function main() {
  const proxyBaseUrl =
    argValue("proxy-url", process.env.PROXY_URL) ?? "http://127.0.0.1:8545";
  const url = new URL("/v1/sign/session-transaction", proxyBaseUrl).toString();
  const clientId = argValue("client-id", process.env.KEYRING_CLIENT_ID) ?? "default";
  const secret = argValue("secret", process.env.KEYRING_HMAC_SECRET);
  if (!secret) {
    throw new Error("Missing HMAC secret: pass --secret or set KEYRING_HMAC_SECRET");
  }

  const chainId =
    argValue("chain-id", process.env.DEMO_CHAIN_ID) ?? "0x534e5f5345504f4c4941";
  const accountAddress = argValue("account-address", process.env.DEMO_ACCOUNT_ADDRESS) ?? "0x111";
  const targetContract = argValue("contract-address", process.env.DEMO_CONTRACT_ADDRESS) ?? "0x222";
  const outputDir =
    argValue("out-dir", process.env.DEMO_OUT_DIR) ??
    path.join("demo", "artifacts", nowIsoCompact());
  await mkdir(outputDir, { recursive: true });

  const run = {
    runId: randomUUID(),
    startedAt: new Date().toISOString(),
    proxyUrl: url,
    clientId,
    cases: {},
  };

  const validUntil = Math.floor(Date.now() / 1000) + 3600;

  const happy = await postSigned({
    url,
    secret,
    clientId,
    nonce: "demo-happy-1",
    timestamp: String(Date.now()),
    body: makeHappyPayload({
      accountAddress,
      chainId,
      nonceHex: "0x1001",
      validUntil,
      contractAddress: targetContract,
    }),
  });
  run.cases.happyPath = happy;
  assertCase("happyPath", happy.status === 200, `expected 200, got ${happy.status}`);
  assertCase(
    "happyPath",
    Array.isArray(happy.body.signature) && happy.body.signature.length === 4,
    "expected 4-felt signature"
  );

  const replayTimestamp = String(Date.now());
  const replayBody = makeHappyPayload({
    accountAddress,
    chainId,
    nonceHex: "0x1002",
    validUntil,
    contractAddress: targetContract,
  });
  const replayFirst = await postSigned({
    url,
    secret,
    clientId,
    nonce: "demo-replay-1",
    timestamp: replayTimestamp,
    body: replayBody,
  });
  const replaySecond = await postSigned({
    url,
    secret,
    clientId,
    nonce: "demo-replay-1",
    timestamp: replayTimestamp,
    body: replayBody,
  });
  run.cases.replay = { first: replayFirst, second: replaySecond };
  assertCase("replay.first", replayFirst.status === 200, `expected 200, got ${replayFirst.status}`);
  assertCase("replay.second", replaySecond.status === 401, `expected 401, got ${replaySecond.status}`);
  assertCase(
    "replay.second",
    typeof replaySecond.body.error === "string" && replaySecond.body.error.includes("replayed nonce"),
    "expected replayed nonce error message"
  );

  const denied = await postSigned({
    url,
    secret,
    clientId,
    nonce: "demo-denied-1",
    timestamp: String(Date.now()),
    body: makeDeniedSelectorPayload({
      accountAddress,
      chainId,
      nonceHex: "0x1003",
      validUntil,
      contractAddress: targetContract,
    }),
  });
  run.cases.policyDeny = denied;
  assertCase("policyDeny", denied.status === 422, `expected 422, got ${denied.status}`);
  assertCase(
    "policyDeny",
    typeof denied.body.error === "string" && denied.body.error.includes("denied selector"),
    "expected denied selector error message"
  );

  run.finishedAt = new Date().toISOString();

  const resultPath = path.join(outputDir, "results.json");
  const summaryPath = path.join(outputDir, "summary.txt");
  await writeFile(resultPath, `${JSON.stringify(run, null, 2)}\n`, "utf8");

  const summary = [
    `Security proof run: ${run.runId}`,
    `Proxy URL: ${run.proxyUrl}`,
    `Output: ${resultPath}`,
    "",
    `happyPath: status=${happy.status}, signatureFelts=${Array.isArray(happy.body.signature) ? happy.body.signature.length : 0}`,
    `replay.first: status=${replayFirst.status}`,
    `replay.second: status=${replaySecond.status}, error=${replaySecond.body.error}`,
    `policyDeny: status=${denied.status}, error=${denied.body.error}`,
  ].join("\n");
  await writeFile(summaryPath, `${summary}\n`, "utf8");
  process.stdout.write(`${summary}\n`);
}

main().catch((error) => {
  process.stderr.write(`Security proof failed: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
