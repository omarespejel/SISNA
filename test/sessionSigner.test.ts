import { describe, expect, it } from "vitest";
import { constants, ec, num, outsideExecution, typedData } from "starknet";
import { SessionTransactionSigner } from "../src/signer/sessionSigner.js";
import { PolicyError } from "../src/signer/policy.js";

const CURVE_ORDER = BigInt(
  "3618502788666131213697322783095070105526743751716087489154079457884512865583",
);

const OUTSIDE_EXECUTION_VERSION_V2 = "2";

function computeMessageHash(req: any): string {
  const accountAddressHex = num.toHex(BigInt(req.accountAddress));
  const chainIdHex = num.toHex(BigInt(req.chainId));
  const outsideTypedData = outsideExecution.getTypedData(
    chainIdHex,
    {
      caller: req.caller ?? constants.OutsideExecutionCallerAny,
      execute_after: req.executeAfter ?? 0,
      execute_before: req.validUntil,
    },
    req.nonce,
    req.calls.map((call: any) => ({
      contractAddress: call.contractAddress,
      entrypoint: call.entrypoint,
      calldata: call.calldata,
    })),
    OUTSIDE_EXECUTION_VERSION_V2,
  );
  return typedData.getMessageHash(outsideTypedData, accountAddressHex);
}

function computeDomainHash(req: any): string {
  const chainIdHex = num.toHex(BigInt(req.chainId));
  const outsideTypedData = outsideExecution.getTypedData(
    chainIdHex,
    {
      caller: req.caller ?? constants.OutsideExecutionCallerAny,
      execute_after: req.executeAfter ?? 0,
      execute_before: req.validUntil,
    },
    req.nonce,
    req.calls.map((call: any) => ({
      contractAddress: call.contractAddress,
      entrypoint: call.entrypoint,
      calldata: call.calldata,
    })),
    OUTSIDE_EXECUTION_VERSION_V2,
  );
  const domainType = (outsideTypedData as { types: Record<string, unknown> }).types.StarknetDomain
    ? "StarknetDomain"
    : "StarkNetDomain";
  return typedData.getStructHash(
    (outsideTypedData as { types: Record<string, unknown> }).types as never,
    domainType,
    (outsideTypedData as { domain: Record<string, unknown> }).domain as never,
    (outsideTypedData as { domain?: { revision?: string } }).domain?.revision as never,
  );
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
    const expectedDomainHash = computeDomainHash(req);
    const outS = BigInt(res.signature[2]);
    expect(outS).toBeLessThanOrEqual(halfOrder);
    expect(num.toHex(outS)).toBe(num.toHex(expectedCanonicalS));
    expect(res.signerProvider).toBe("local");
    expect(res.signatureMode).toBe("v2_snip12");
    expect(res.signatureKind).toBe("Snip12");
    expect(res.domainHash).toBe(expectedDomainHash);
  });
  it("normalizes malformed accountAddress failures into PolicyError", () => {
    const signer = new SessionTransactionSigner(
      [{ keyId: "default", privateKey: "0x1", publicKey: undefined }],
      "default",
      new Map(),
      new Map([["client", new Set(["0x111"])]]),
      { maxValidityWindowSec: 24 * 60 * 60, allowedChainIds: new Set() },
    );

    expect(() =>
      signer.sign({
        accountAddress: "-1",
        chainId: "0x534e5f5345504f4c4941",
        nonce: "0x1",
        validUntil: Math.floor(Date.now() / 1000) + 3600,
        calls: [
          {
            contractAddress: "0x222",
            entrypoint: "transfer",
            calldata: ["0x1", "0x0"],
          },
        ],
      }, "client")).toThrow(PolicyError);
  });
});
