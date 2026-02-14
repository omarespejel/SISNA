import { describe, expect, it, vi } from "vitest";
import { ec, num } from "starknet";
import { SessionTransactionSigner } from "../src/signer/sessionSigner.js";

function hex(n: bigint): string {
  return `0x${n.toString(16)}`;
}

describe("SessionTransactionSigner canonical s", () => {
  it("normalizes high-s signatures to low-s form", () => {
    const signer = new SessionTransactionSigner(
      [{ keyId: "default", privateKey: "0x1", publicKey: undefined }],
      "default",
      new Map(),
      new Map(),
      { maxValidityWindowSec: 24 * 60 * 60, allowedChainIds: new Set() },
    );

    const CURVE_ORDER = BigInt(
      "3618502788666131213697322783095070105526743751716087489154079457884512865583",
    );
    const halfOrder = CURVE_ORDER >> 1n;
    const highS = CURVE_ORDER - 1n; // definitely > n/2

    const spy = vi.spyOn(ec.starkCurve, "sign").mockReturnValue({
      r: hex(123n),
      s: hex(highS),
    } as unknown as ReturnType<typeof ec.starkCurve.sign>);

    const req = {
      accountAddress: "0x111",
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
    };

    const res = signer.sign(req as any, "client");
    const s = BigInt(res.signature[2]);
    expect(s).toBeLessThanOrEqual(halfOrder);
    expect(num.toHex(s)).toBe(num.toHex(CURVE_ORDER - highS));

    spy.mockRestore();
  });
});

