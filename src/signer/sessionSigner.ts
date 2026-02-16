import { ec, hash, num } from "starknet";
import type { SignSessionTransactionRequest } from "../types/api.js";
import { PolicyError, assertSigningPolicy, type SigningPolicyConfig } from "./policy.js";
import type { SigningKeyConfig } from "../config.js";
import { normalizeFelt } from "../utils/felt.js";

export type SignatureResult = {
  sessionPublicKey: string;
  messageHash: string;
  signature: [string, string, string, string];
};

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

    const hashData: bigint[] = [
      BigInt(normalizedAccount),
      BigInt(req.chainId),
      BigInt(req.nonce),
      BigInt(req.validUntil),
    ];

    for (const call of req.calls) {
      hashData.push(BigInt(call.contractAddress));

      const selector = call.entrypoint.startsWith("0x")
        ? BigInt(call.entrypoint)
        : BigInt(hash.getSelectorFromName(call.entrypoint));
      hashData.push(selector);

      hashData.push(BigInt(call.calldata.length));
      for (const d of call.calldata) {
        hashData.push(BigInt(d));
      }
    }

    const messageHash = hash.computePoseidonHashOnElements(hashData.map((x) => num.toHex(x)));
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
      sessionPublicKey: key.sessionPublicKey,
      messageHash,
      signature: [
        key.sessionPublicKey,
        num.toHex(rawSig.r),
        num.toHex(canonicalS),
        num.toHex(req.validUntil),
      ],
    };
  }
}
