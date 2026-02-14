#!/usr/bin/env node

import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  Account,
  EDataAvailabilityMode,
  ETransactionVersion,
  RpcProvider,
  SignerInterface,
  cairo,
  num,
} from "starknet";

function argValue(name, fallback = undefined) {
  const idx = process.argv.indexOf(`--${name}`);
  if (idx === -1 || idx + 1 >= process.argv.length) {
    return fallback;
  }
  return process.argv[idx + 1];
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

function toFeltHex(value) {
  if (typeof value === "string" && value.startsWith("0x")) {
    return value;
  }
  return num.toHex(value);
}

class RemoteSessionSigner extends SignerInterface {
  constructor(config) {
    super();
    this.config = config;
    this.lastSignatureMeta = null;
  }

  async getPubKey() {
    if (!this.lastSignatureMeta?.sessionPublicKey) {
      throw new Error("Session pubkey unavailable before first signature");
    }
    return this.lastSignatureMeta.sessionPublicKey;
  }

  async signMessage() {
    throw new Error("RemoteSessionSigner does not support signMessage");
  }

  async signDeployAccountTransaction() {
    throw new Error("RemoteSessionSigner cannot sign deploy account transactions");
  }

  async signDeclareTransaction() {
    throw new Error("RemoteSessionSigner cannot sign declare transactions");
  }

  async signTransaction(transactions, txDetails) {
    const validUntil = Math.floor(Date.now() / 1000) + this.config.validitySec;
    const body = {
      accountAddress: this.config.accountAddress,
      keyId: this.config.keyId,
      chainId: toFeltHex(txDetails.chainId),
      nonce: toFeltHex(txDetails.nonce),
      validUntil,
      calls: transactions.map((call) => ({
        contractAddress: call.contractAddress,
        entrypoint: call.entrypoint,
        calldata: (call.calldata ?? []).map((x) =>
          typeof x === "string" ? x : num.toHex(x)
        ),
      })),
      context: {
        requester: "e2e-sepolia-proof",
        tool: "starknet_transfer",
        reason: "e2e-proof",
      },
    };

    const rawBody = JSON.stringify(body);
    const ts = String(Date.now());
    const nonce = randomBytes(16).toString("hex");
    const endpoint = new URL("/v1/sign/session-transaction", this.config.proxyBaseUrl);
    const payload = buildSigningPayload({
      timestamp: ts,
      nonce,
      method: "POST",
      pathWithQuery: `${endpoint.pathname}${endpoint.search}`,
      rawBody,
    });
    const signature = computeHmacHex(this.config.hmacSecret, payload);

    const res = await fetch(endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-keyring-client-id": this.config.clientId,
        "x-keyring-timestamp": ts,
        "x-keyring-nonce": nonce,
        "x-keyring-signature": signature,
      },
      body: rawBody,
    });

    const text = await res.text();
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = { raw: text };
    }

    if (!res.ok) {
      throw new Error(
        `Proxy sign failed (${res.status}): ${typeof parsed.error === "string" ? parsed.error : text}`
      );
    }
    if (!Array.isArray(parsed.signature) || parsed.signature.length !== 4) {
      throw new Error("Unexpected proxy signature payload");
    }

    this.lastSignatureMeta = {
      requestId: parsed.requestId,
      messageHash: parsed.messageHash,
      sessionPublicKey: parsed.sessionPublicKey,
      validUntil,
    };
    return parsed.signature;
  }
}

function findCorrelatedLogLine(logRaw, requestId) {
  const lines = logRaw.split("\n");
  for (let i = lines.length - 1; i >= 0; i -= 1) {
    const line = lines[i];
    if (!line.trim()) {
      continue;
    }
    try {
      const parsed = JSON.parse(line);
      if (
        parsed?.request_id === requestId
          && parsed?.event === "sign.session_transaction.success"
      ) {
        return parsed;
      }
    } catch {
      // ignore non-json
    }
  }
  return null;
}

async function main() {
  const rpcUrl = argValue("rpc-url", process.env.DEMO_SEPOLIA_RPC_URL);
  const accountAddress = argValue("account-address", process.env.DEMO_ACCOUNT_ADDRESS);
  const tokenAddress = argValue("token-address", process.env.DEMO_TOKEN_ADDRESS);
  const recipientAddress = argValue("recipient-address", process.env.DEMO_RECIPIENT_ADDRESS);
  const amountRaw = BigInt(argValue("amount-raw", process.env.DEMO_AMOUNT_RAW ?? "1"));
  const proxyBaseUrl = argValue("proxy-url", process.env.PROXY_BASE_URL ?? "http://127.0.0.1:8654");
  const hmacSecret = argValue("secret", process.env.KEYRING_HMAC_SECRET);
  const clientId = argValue("client-id", process.env.KEYRING_CLIENT_ID ?? "default");
  const keyId = argValue("key-id", process.env.KEYRING_KEY_ID);
  const validitySec = Number(argValue("validity-sec", process.env.DEMO_VALIDITY_SEC ?? "300"));
  const waitForReceipt = (argValue("wait", process.env.DEMO_WAIT_FOR_RECEIPT ?? "true") ?? "true") !== "false";
  const proxyLogPath = argValue("proxy-log-path", process.env.DEMO_PROXY_LOG_PATH);
  const outDir = argValue(
    "out-dir",
    process.env.DEMO_OUT_DIR ?? path.join("demo", "artifacts", new Date().toISOString().replace(/[:.]/g, "-")),
  );

  if (!rpcUrl || !accountAddress || !tokenAddress || !recipientAddress || !hmacSecret) {
    throw new Error(
      "Missing required inputs. Need rpc-url/account-address/token-address/recipient-address and HMAC secret."
    );
  }

  await mkdir(outDir, { recursive: true });
  const runId = randomUUID();
  const provider = new RpcProvider({
    nodeUrl: rpcUrl,
    batch: 0,
    resourceBoundsOverhead: {
      l1_gas: { max_amount: 50, max_price_per_unit: 50 },
      // Sepolia can under-estimate l1_data_gas on V3 by >50% in edge cases.
      l1_data_gas: { max_amount: 120, max_price_per_unit: 50 },
      l2_gas: { max_amount: 50, max_price_per_unit: 50 },
    },
  });
  const signer = new RemoteSessionSigner({
    proxyBaseUrl,
    hmacSecret,
    clientId,
    accountAddress,
    validitySec,
    keyId,
  });

  const account = new Account({
    provider,
    address: accountAddress,
    signer,
    transactionVersion: ETransactionVersion.V3,
  });

  const amount = cairo.uint256(amountRaw);
  const transferCall = {
    contractAddress: tokenAddress,
    entrypoint: "transfer",
    calldata: [recipientAddress, num.toHex(amount.low), num.toHex(amount.high)],
  };

  const startedAt = new Date().toISOString();
  let executionMode = "v3-default";
  let tx;
  try {
    tx = await account.execute(transferCall);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    // Retry once with explicitly bumped resource bounds when v3 l1_data_gas is under-estimated.
    if (message.includes("Insufficient max L1DataGas")) {
      const estimate = await account.estimateInvokeFee(transferCall, { skipValidate: false });
      const rb = estimate.resourceBounds;
      const bump = (x, percent) => (BigInt(x) * BigInt(100 + percent)) / 100n;
      const bumpedResourceBounds = {
        l1_gas: {
          max_amount: bump(rb.l1_gas.max_amount, 30),
          max_price_per_unit: bump(rb.l1_gas.max_price_per_unit, 20),
        },
        l1_data_gas: {
          max_amount: bump(rb.l1_data_gas.max_amount, 120),
          max_price_per_unit: bump(rb.l1_data_gas.max_price_per_unit, 20),
        },
        l2_gas: {
          max_amount: bump(rb.l2_gas.max_amount, 30),
          max_price_per_unit: bump(rb.l2_gas.max_price_per_unit, 20),
        },
      };

      tx = await account.execute(transferCall, {
        tip: 0n,
        paymasterData: [],
        accountDeploymentData: [],
        nonceDataAvailabilityMode: EDataAvailabilityMode.L1,
        feeDataAvailabilityMode: EDataAvailabilityMode.L1,
        resourceBounds: bumpedResourceBounds,
      });
      executionMode = "v3-bumped-resource-bounds";
    } else {
      throw error;
    }
  }
  const txHash = tx.transaction_hash;
  let receiptStatus = "not_waited";
  if (waitForReceipt) {
    await provider.waitForTransaction(txHash, { retries: 40, retryInterval: 3_000 });
    receiptStatus = "accepted_or_included";
  }

  const signerMeta = signer.lastSignatureMeta;
  let correlatedLogEvent = null;
  if (proxyLogPath && signerMeta?.requestId) {
    try {
      const rawLog = await readFile(proxyLogPath, "utf8");
      correlatedLogEvent = findCorrelatedLogLine(rawLog, signerMeta.requestId);
    } catch {
      correlatedLogEvent = null;
    }
  }

  const result = {
    runId,
    startedAt,
    finishedAt: new Date().toISOString(),
    network: "starknet-sepolia",
    rpcUrl,
    txHash,
    executionMode,
    receiptStatus,
    requestId: signerMeta?.requestId ?? null,
    messageHash: signerMeta?.messageHash ?? null,
    sessionPublicKey: signerMeta?.sessionPublicKey ?? null,
    correlation: {
      proxyLogPath: proxyLogPath ?? null,
      matchedSignerLog: correlatedLogEvent,
    },
    transfer: {
      accountAddress,
      tokenAddress,
      recipientAddress,
      amountRaw: amountRaw.toString(),
    },
  };

  const resultPath = path.join(outDir, "e2e-sepolia-proof.json");
  await writeFile(resultPath, `${JSON.stringify(result, null, 2)}\n`, "utf8");

  const summaryLines = [
    `E2E run: ${runId}`,
    `txHash: ${txHash}`,
    `requestId: ${result.requestId}`,
    `messageHash: ${result.messageHash}`,
    `receiptStatus: ${receiptStatus}`,
    `correlatedSignerLog: ${correlatedLogEvent ? "yes" : "no"}`,
    `artifact: ${resultPath}`,
  ];
  const summary = summaryLines.join("\n");
  await writeFile(path.join(outDir, "e2e-sepolia-proof.txt"), `${summary}\n`, "utf8");
  process.stdout.write(`${summary}\n`);
}

main().catch((error) => {
  process.stderr.write(`E2E sepolia proof failed: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
