import { describe, expect, it } from "vitest";
import { buildSigningPayload, computeHmacHex } from "../src/auth/hmac.js";

describe("hmac payload", () => {
  it("produces deterministic signatures", () => {
    const payload = buildSigningPayload({
      timestamp: "1700000000000",
      nonce: "nonce-1",
      method: "POST",
      path: "/v1/sign/session-transaction",
      rawBody: '{"a":1}',
    });

    const sig1 = computeHmacHex("secret-value", payload);
    const sig2 = computeHmacHex("secret-value", payload);

    expect(sig1).toBe(sig2);
    expect(sig1).toMatch(/^[a-f0-9]{64}$/);
  });
});
