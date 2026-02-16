import { describe, expect, it } from "vitest";
import { ec, hash, num, shortString } from "starknet";
import { SessionTransactionSigner } from "../src/signer/sessionSigner.js";

const CURVE_ORDER = BigInt(
  "3618502788666131213697322783095070105526743751716087489154079457884512865583",
);

const STARKNET_DOMAIN_TYPE_HASH_REV1 =
  "0x1ff2f602e42168014d405a94f75e8a93d640751d71d16311266e140d8b0a210";
const SESSION_DOMAIN_NAME = shortString.encodeShortString("Session.transaction");
const STARKNET_MESSAGE_PREFIX = shortString.encodeShortString("StarkNet Message");
const SESSION_DOMAIN_VERSION = num.toHex(2);
const SNIP12_REVISION = num.toHex(1);

function computeMessageHash(req: any): string {
  const accountAddressHex = num.toHex(BigInt(req.accountAddress));
  const chainIdHex = num.toHex(BigInt(req.chainId));
  const nonceHex = num.toHex(BigInt(req.nonce));
  const validUntilHex = num.toHex(req.validUntil);

  const hashData: string[] = [
    accountAddressHex,
    chainIdHex,
    nonceHex,
    validUntilHex,
  ];

  for (const call of req.calls) {
    hashData.push(num.toHex(BigInt(call.contractAddress)));
    const selector = call.entrypoint.startsWith("0x")
      ? BigInt(call.entrypoint)
      : BigInt(hash.getSelectorFromName(call.entrypoint));
    hashData.push(num.toHex(selector));

    hashData.push(num.toHex(call.calldata.length));
    for (const d of call.calldata) {
      hashData.push(num.toHex(BigInt(d)));
    }
  }

  const payloadHash = hash.computePoseidonHashOnElements(hashData);
  const domainHash = hash.computePoseidonHashOnElements([
    STARKNET_DOMAIN_TYPE_HASH_REV1,
    SESSION_DOMAIN_NAME,
    SESSION_DOMAIN_VERSION,
    chainIdHex,
    SNIP12_REVISION,
  ]);
  return hash.computePoseidonHashOnElements([
    STARKNET_MESSAGE_PREFIX,
    domainHash,
    accountAddressHex,
    payloadHash,
  ]);
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
    const chainIdHex = num.toHex(BigInt(req.chainId));
    const expectedDomainHash = hash.computePoseidonHashOnElements([
      STARKNET_DOMAIN_TYPE_HASH_REV1,
      SESSION_DOMAIN_NAME,
      SESSION_DOMAIN_VERSION,
      chainIdHex,
      SNIP12_REVISION,
    ]);
    const outS = BigInt(res.signature[2]);
    expect(outS).toBeLessThanOrEqual(halfOrder);
    expect(num.toHex(outS)).toBe(num.toHex(expectedCanonicalS));
    expect(res.signatureMode).toBe("v2_snip12");
    expect(res.domainHash).toBe(expectedDomainHash);
  });
});
