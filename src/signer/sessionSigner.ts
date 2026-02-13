import { ec, hash, num } from "starknet";
import type { SignSessionTransactionRequest } from "../types/api.js";
import { assertSigningPolicy, type SigningPolicyConfig } from "./policy.js";

export type SignatureResult = {
  sessionPublicKey: string;
  messageHash: string;
  signature: [string, string, string, string];
};

export class SessionTransactionSigner {
  readonly sessionPublicKey: string;

  constructor(
    private readonly privateKey: string,
    private readonly signingPolicy: SigningPolicyConfig,
    expectedPublicKey?: string,
  ) {
    this.sessionPublicKey = ec.starkCurve.getStarkKey(privateKey);

    if (expectedPublicKey && expectedPublicKey.toLowerCase() !== this.sessionPublicKey.toLowerCase()) {
      throw new Error("SESSION_PUBLIC_KEY does not match SESSION_PRIVATE_KEY");
    }
  }

  sign(req: SignSessionTransactionRequest): SignatureResult {
    assertSigningPolicy(req, this.signingPolicy);

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
    const rawSig = ec.starkCurve.sign(messageHash, this.privateKey);

    return {
      sessionPublicKey: this.sessionPublicKey,
      messageHash,
      signature: [
        this.sessionPublicKey,
        num.toHex(rawSig.r),
        num.toHex(rawSig.s),
        num.toHex(req.validUntil),
      ],
    };
  }
}
