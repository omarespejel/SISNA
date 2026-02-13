import { ec, hash, num } from "starknet";
import type { SignSessionTransactionRequest } from "../types/api.js";
import { PolicyError, assertSigningPolicy, type SigningPolicyConfig } from "./policy.js";
import type { SigningKeyConfig } from "../config.js";

export type SignatureResult = {
  sessionPublicKey: string;
  messageHash: string;
  signature: [string, string, string, string];
};

export class SessionTransactionSigner {
  readonly defaultKeyId: string;
  private readonly signingKeysById: Map<string, { privateKey: string; sessionPublicKey: string }>;

  constructor(
    signingKeys: SigningKeyConfig[],
    defaultKeyId: string,
    private readonly signingPolicy: SigningPolicyConfig,
  ) {
    this.defaultKeyId = defaultKeyId;
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

  sign(req: SignSessionTransactionRequest): SignatureResult {
    assertSigningPolicy(req, this.signingPolicy);
    const requestedKeyId = req.keyId ?? this.defaultKeyId;
    const key = this.signingKeysById.get(requestedKeyId);
    if (!key) {
      throw new PolicyError(`Unknown keyId: ${requestedKeyId}`);
    }

    const hashData: bigint[] = [
      BigInt(req.accountAddress),
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

    return {
      sessionPublicKey: key.sessionPublicKey,
      messageHash,
      signature: [
        key.sessionPublicKey,
        num.toHex(rawSig.r),
        num.toHex(rawSig.s),
        num.toHex(req.validUntil),
      ],
    };
  }
}
