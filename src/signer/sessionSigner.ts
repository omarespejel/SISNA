import { constants, ec, num, outsideExecution, typedData } from "starknet";
import type { SignSessionTransactionRequest } from "../types/api.js";
import { PolicyError, assertSigningPolicy, type SigningPolicyConfig } from "./policy.js";
import type { SigningKeyConfig } from "../config.js";
import { normalizeFelt } from "../utils/felt.js";

const OUTSIDE_EXECUTION_VERSION_V2 = "2";

export type SignatureResult = {
  signerProvider: "local" | "dfns";
  sessionPublicKey: string;
  signatureMode: "v2_snip12";
  signatureKind: "Snip12";
  domainHash: string;
  messageHash: string;
  signature: [string, string, string, string];
};

export type SessionSigningHashes = {
  accountAddressHex: string;
  validUntilHex: string;
  domainHash: string;
  messageHash: string;
};

export function computeSessionSigningHashes(
  req: SignSessionTransactionRequest,
  normalizedAccountAddress?: string,
): SessionSigningHashes {
  const accountAddressHex = num.toHex(BigInt(normalizedAccountAddress ?? normalizeFelt(req.accountAddress)));
  const chainIdHex = num.toHex(BigInt(req.chainId));
  const validUntilHex = num.toHex(req.validUntil);
  const caller = req.caller
    ? num.toHex(BigInt(req.caller))
    : constants.OutsideExecutionCallerAny;
  const executeAfter = req.executeAfter ? num.toHex(BigInt(req.executeAfter)) : 0;
  const outsideTypedData = outsideExecution.getTypedData(
    chainIdHex,
    {
      caller,
      execute_after: executeAfter,
      execute_before: req.validUntil,
    },
    req.nonce,
    req.calls.map((call) => ({
      contractAddress: call.contractAddress,
      entrypoint: call.entrypoint,
      calldata: call.calldata,
    })),
    OUTSIDE_EXECUTION_VERSION_V2,
  );
  const domainType = (outsideTypedData as { types: Record<string, unknown> }).types.StarknetDomain
    ? "StarknetDomain"
    : "StarkNetDomain";
  const domainHash = typedData.getStructHash(
    (outsideTypedData as { types: Record<string, unknown> }).types as never,
    domainType,
    (outsideTypedData as { domain: Record<string, unknown> }).domain as never,
    (outsideTypedData as { domain?: { revision?: string } }).domain?.revision as never,
  );
  const messageHash = typedData.getMessageHash(outsideTypedData, accountAddressHex);
  return {
    accountAddressHex,
    validUntilHex,
    domainHash,
    messageHash,
  };
}

export class SessionTransactionSigner {
  readonly defaultKeyId: string;
  private readonly signingKeysById: Map<string, { privateKey: string; sessionPublicKey: string }>;
  private readonly allowedKeyIdsByClient: Map<string, Set<string> | undefined>;
  private readonly allowedAccountsByClient: Map<string, Set<string> | undefined>;

  constructor(
    signingKeys: SigningKeyConfig[],
    defaultKeyId: string,
    allowedKeyIdsByClient: Map<string, Set<string> | undefined>,
    allowedAccountsByClient: Map<string, Set<string> | undefined>,
    private readonly signingPolicy: SigningPolicyConfig,
  ) {
    this.defaultKeyId = defaultKeyId;
    this.allowedKeyIdsByClient = allowedKeyIdsByClient;
    this.allowedAccountsByClient = allowedAccountsByClient;
    this.signingKeysById = new Map();

    for (const key of signingKeys) {
      const sessionPublicKey = ec.starkCurve.getStarkKey(key.privateKey);
      if (key.publicKey && key.publicKey.toLowerCase() !== sessionPublicKey.toLowerCase()) {
        throw new Error(`Public key does not match private key for keyId=${key.keyId}`);
      }
      this.signingKeysById.set(key.keyId, {
        privateKey: key.privateKey,
        sessionPublicKey,
      });
    }

    if (!this.signingKeysById.has(defaultKeyId)) {
      throw new Error(`Default keyId is not configured: ${defaultKeyId}`);
    }
  }

  sign(req: SignSessionTransactionRequest, clientId: string): SignatureResult {
    assertSigningPolicy(req, this.signingPolicy);
    const requestedKeyId = req.keyId ?? this.defaultKeyId;
    const allowedKeyIds = this.allowedKeyIdsByClient.get(clientId);
    if (allowedKeyIds && !allowedKeyIds.has(requestedKeyId)) {
      throw new PolicyError(`client ${clientId} is not allowed to use keyId ${requestedKeyId}`);
    }
    let normalizedAccount: string;
    try {
      normalizedAccount = normalizeFelt(req.accountAddress);
    } catch {
      throw new PolicyError(`invalid felt value: ${req.accountAddress}`);
    }
    const allowedAccounts = this.allowedAccountsByClient.get(clientId);
    if (allowedAccounts && !allowedAccounts.has(normalizedAccount)) {
      throw new PolicyError(`client ${clientId} is not allowed to sign for account ${req.accountAddress}`);
    }
    const key = this.signingKeysById.get(requestedKeyId);
    if (!key) {
      throw new PolicyError(`Unknown keyId: ${requestedKeyId}`);
    }

    const { validUntilHex, domainHash, messageHash } = computeSessionSigningHashes(req, normalizedAccount);
    const rawSig = ec.starkCurve.sign(messageHash, key.privateKey);

    // Enforce canonical s (s <= n/2) to prevent signature malleability.
    // starknet.js defaults to lowS: false, so we normalize here.
    const CURVE_ORDER = BigInt(
      "3618502788666131213697322783095070105526743751716087489154079457884512865583",
    );
    const halfOrder = CURVE_ORDER >> 1n;
    const s = BigInt(rawSig.s);
    const canonicalS = s > halfOrder ? CURVE_ORDER - s : s;

    return {
      signerProvider: "local",
      sessionPublicKey: key.sessionPublicKey,
      signatureMode: "v2_snip12",
      signatureKind: "Snip12",
      domainHash,
      messageHash,
      signature: [
        key.sessionPublicKey,
        num.toHex(rawSig.r),
        num.toHex(canonicalS),
        validUntilHex,
      ],
    };
  }
}
