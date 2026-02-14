import { describe, expect, it } from "vitest";
import { InMemoryNonceStore } from "../src/auth/nonceStore.js";

describe("in-memory nonce store", () => {
  it("rejects nonce replay within ttl window", () => {
    const store = new InMemoryNonceStore(10_000);
    const now = 1_000;

    expect(store.consume("nonce-1", now)).toBe(true);
    expect(store.consume("nonce-1", now + 1)).toBe(false);
  });

  it("accepts nonce again after ttl expiry", () => {
    const store = new InMemoryNonceStore(5_000);
    const now = 1_000;

    expect(store.consume("nonce-2", now)).toBe(true);
    expect(store.consume("nonce-2", now + 5_001)).toBe(true);
  });

  it("periodically garbage-collects expired nonce entries", () => {
    const store = new InMemoryNonceStore(1);

    expect(store.consume("nonce-gc-target", 1)).toBe(true);
    for (let i = 0; i < 64; i += 1) {
      expect(store.consume(`nonce-${i}`, 10_000 + i)).toBe(true);
    }

    expect(store.consume("nonce-gc-target", 11_000)).toBe(true);
  });
});
