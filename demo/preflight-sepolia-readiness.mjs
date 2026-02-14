#!/usr/bin/env node

import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { RpcProvider, num } from "starknet";

const ETH_TOKEN_ADDRESS =
  "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7";
const STRK_TOKEN_ADDRESS =
  "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";

function argValue(name, fallback = undefined) {
  const idx = process.argv.indexOf(`--${name}`);
  if (idx === -1 || idx + 1 >= process.argv.length) return fallback;
  return process.argv[idx + 1];
}

function normalizeHex(value) {
  const lower = String(value).toLowerCase();
  return lower.startsWith("0x") ? lower : `0x${lower}`;
}

function fromU256Words(words) {
  if (!Array.isArray(words) || words.length === 0) return 0n;
  const low = BigInt(words[0]);
  if (words.length === 1) return low;
  const high = BigInt(words[1]);
  return low + (high << 128n);
}

function fmtAmount(raw, decimals = 18n, maxFrac = 6) {
  const base = 10n ** decimals;
  const whole = raw / base;
  const frac = raw % base;
  if (frac === 0n) return whole.toString();
  const fracStr = frac.toString().padStart(Number(decimals), "0").slice(0, maxFrac).replace(/0+$/, "");
  return fracStr ? `${whole}.${fracStr}` : whole.toString();
}

async function readErc20Balance(provider, tokenAddress, accountAddress) {
  const result = await provider.callContract({
    contractAddress: tokenAddress,
    entrypoint: "balanceOf",
    calldata: [accountAddress],
  });
  return fromU256Words(result);
}

function findEntrypointMissingError(errMsg) {
  const lower = errMsg.toLowerCase();
  return lower.includes("requested entrypoint does not exist");
}

async function checkSessionEntrypoint(provider, accountAddress) {
  try {
    await provider.callContract({
      contractAddress: accountAddress,
      entrypoint: "compute_session_message_hash",
      calldata: [],
    });
    return { ok: true, note: "compute_session_message_hash is callable." };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (findEntrypointMissingError(msg)) {
      return {
        ok: false,
        note: "compute_session_message_hash entrypoint is missing (account is not session-enabled for this flow).",
      };
    }
    return {
      ok: true,
      note: "compute_session_message_hash appears present (call reverted for calldata/runtime reason, not missing entrypoint).",
      debugError: msg,
    };
  }
}

async function main() {
  const rpcUrl = argValue("rpc-url", process.env.DEMO_SEPOLIA_RPC_URL);
  const accountAddress = argValue("account-address", process.env.DEMO_ACCOUNT_ADDRESS);
  const tokenAddress = argValue("token-address", process.env.DEMO_TOKEN_ADDRESS);
  const outDir = argValue(
    "out-dir",
    process.env.DEMO_OUT_DIR ?? path.join("demo", "artifacts", new Date().toISOString().replace(/[:.]/g, "-")),
  );
  const feeTokenSymbol = (argValue("fee-token", process.env.DEMO_FEE_TOKEN ?? "STRK") ?? "STRK").toUpperCase();
  const minFeeTokenWei = BigInt(
    argValue("min-fee-token-wei", process.env.DEMO_MIN_FEE_TOKEN_WEI ?? "1000000000000000"),
  );
  const ethTokenAddress = normalizeHex(argValue("eth-token", process.env.DEMO_ETH_TOKEN_ADDRESS ?? ETH_TOKEN_ADDRESS));
  const strkTokenAddress = normalizeHex(argValue("strk-token", process.env.DEMO_STRK_TOKEN_ADDRESS ?? STRK_TOKEN_ADDRESS));

  if (!rpcUrl || !accountAddress || !tokenAddress) {
    throw new Error("Missing required inputs. Need rpc-url/account-address/token-address.");
  }

  await mkdir(outDir, { recursive: true });
  const provider = new RpcProvider({ nodeUrl: rpcUrl, batch: 0 });

  const checks = [];
  const push = (name, ok, detail, extra = {}) => checks.push({ name, ok, detail, ...extra });

  try {
    const chainId = await provider.getChainId();
    const chainIdHex = num.toHex(chainId);
    const isSepolia =
      String(chainId).toUpperCase() === "SN_SEPOLIA"
      || chainIdHex.toLowerCase() === "0x534e5f5345504f4c4941";
    push(
      "rpc.chain_id",
      isSepolia,
      isSepolia
        ? `Connected to Sepolia (${chainIdHex}).`
        : `Connected chain is ${chainIdHex}, expected Sepolia.`,
      { value: chainIdHex },
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    push("rpc.chain_id", false, `Unable to read chain id: ${msg}`);
  }

  try {
    const classHash = await provider.getClassHashAt(accountAddress);
    push("account.deployed", true, `Account deployed with class hash ${classHash}.`, { classHash });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    push("account.deployed", false, `Account not deployed/reachable: ${msg}`);
  }

  try {
    const classHash = await provider.getClassHashAt(tokenAddress);
    push("token.deployed", true, `Token contract deployed with class hash ${classHash}.`, { classHash });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    push("token.deployed", false, `Token contract not deployed/reachable: ${msg}`);
  }

  const sessionEntrypointCheck = await checkSessionEntrypoint(provider, accountAddress);
  push("account.session_entrypoint", sessionEntrypointCheck.ok, sessionEntrypointCheck.note, {
    debugError: sessionEntrypointCheck.debugError,
  });

  let ethBalance = null;
  let strkBalance = null;
  try {
    ethBalance = await readErc20Balance(provider, ethTokenAddress, accountAddress);
    push("balance.eth", true, `ETH balance: ${fmtAmount(ethBalance)} ETH (${ethBalance} wei).`, {
      wei: ethBalance.toString(),
      tokenAddress: ethTokenAddress,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    push("balance.eth", false, `Failed to read ETH balance: ${msg}`, { tokenAddress: ethTokenAddress });
  }

  try {
    strkBalance = await readErc20Balance(provider, strkTokenAddress, accountAddress);
    push("balance.strk", true, `STRK balance: ${fmtAmount(strkBalance)} STRK (${strkBalance} wei).`, {
      wei: strkBalance.toString(),
      tokenAddress: strkTokenAddress,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    push("balance.strk", false, `Failed to read STRK balance: ${msg}`, { tokenAddress: strkTokenAddress });
  }

  const feeTokenBalance =
    feeTokenSymbol === "ETH" ? ethBalance : feeTokenSymbol === "STRK" ? strkBalance : null;
  if (feeTokenBalance === null) {
    push(
      "balance.fee_token_min",
      false,
      `Unsupported fee token symbol '${feeTokenSymbol}'. Use ETH or STRK, or override script as needed.`,
    );
  } else {
    const enough = feeTokenBalance >= minFeeTokenWei;
    push(
      "balance.fee_token_min",
      enough,
      enough
        ? `${feeTokenSymbol} balance is above minimum (${minFeeTokenWei} wei).`
        : `${feeTokenSymbol} balance is below minimum (${minFeeTokenWei} wei).`,
      { token: feeTokenSymbol, minimumWei: minFeeTokenWei.toString(), currentWei: feeTokenBalance.toString() },
    );
  }

  const ready = checks.every((c) => c.ok);
  const report = {
    generatedAt: new Date().toISOString(),
    network: "starknet-sepolia",
    rpcUrl,
    accountAddress,
    tokenAddress,
    feeTokenSymbol,
    minimumFeeTokenWei: minFeeTokenWei.toString(),
    ready,
    checks,
  };

  const reportPath = path.join(outDir, "preflight-sepolia-readiness.json");
  const summaryPath = path.join(outDir, "preflight-sepolia-readiness.txt");

  const summary = [
    `ready=${ready ? "yes" : "no"}`,
    ...checks.map((c) => `${c.ok ? "PASS" : "FAIL"} ${c.name}: ${c.detail}`),
  ].join("\n");

  await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  await writeFile(summaryPath, `${summary}\n`, "utf8");

  console.log(summary);
  console.log(`\nartifact_json=${reportPath}`);
  console.log(`artifact_txt=${summaryPath}`);

  if (!ready) process.exit(2);
}

main().catch((err) => {
  const msg = err instanceof Error ? err.message : String(err);
  console.error(`preflight failed: ${msg}`);
  process.exit(1);
});

