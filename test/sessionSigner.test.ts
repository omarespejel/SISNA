import { describe, expect, it } from "vitest";
import { ec, hash, num } from "starknet";
import { SessionTransactionSigner } from "../src/signer/sessionSigner.js";

const CURVE_ORDER = BigInt(
  "3618502788666131213697322783095070105526743751716087489154079457884512865583",
);

function computeMessageHash(req: any): string {
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

  return hash.computePoseidonHashOnElements(hashData.map((x) => num.toHex(x)));
}

describe("SessionTransactionSigner canonical s", () => {
  it("always returns low-s signatures (s <= n/2)", () => {
    const signer = new SessionTransactionSigner(
      [{ keyId: "default", privateKey: "0x1", publicKey: undefined }],
      "default",
      new Map(),
      new Map(),
      { maxValidityWindowSec: 24 * 60 * 60, allowedChainIds: new Set() },
    );

    const halfOrder = CURVE_ORDER >> 1n;
    const privateKey = "0x1";

    // Find a case where starknet.js produces a high-s signature, then verify
    // the signer normalizes it.
    let found: { req: any; rawS: bigint } | null = null;
    for (let i = 0; i < 64; i++) {
      const req = {
        accountAddress: "0x111",
        chainId: "0x534e5f5345504f4c4941",
        nonce: `0x${(i + 1).toString(16)}`,
        validUntil: Math.floor(Date.now() / 1000) + 3600,
        calls: [
          {
            contractAddress: "0x222",
            entrypoint: "transfer",
            calldata: ["0x1", "0x0"],
          },
        ],
      };

      const msgHash = computeMessageHash(req);
      const rawSig = ec.starkCurve.sign(msgHash, privateKey);
      const rawS = BigInt(rawSig.s);
      if (rawS > halfOrder) {
        found = { req, rawS };
        break;
      }
    }

    expect(found).not.toBeNull();
    const { req, rawS } = found!;
    const expectedCanonicalS = rawS > halfOrder ? CURVE_ORDER - rawS : rawS;

    const res = signer.sign(req, "client");
    const outS = BigInt(res.signature[2]);
    expect(outS).toBeLessThanOrEqual(halfOrder);
    expect(num.toHex(outS)).toBe(num.toHex(expectedCanonicalS));
  });
});

