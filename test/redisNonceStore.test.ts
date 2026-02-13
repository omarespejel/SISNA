import { describe, expect, it, vi } from "vitest";
import { RedisNonceStore, type RedisNonceClient } from "../src/auth/redisNonceStore.js";

describe("RedisNonceStore", () => {
  it("accepts first nonce and rejects replay", async () => {
    const setMock = vi
      .fn<RedisNonceClient["set"]>()
      .mockResolvedValueOnce("OK")
      .mockResolvedValueOnce(null);

    const store = new RedisNonceStore({ set: setMock }, 10_000, "nonce:");

    await expect(store.consume("abc", Date.now())).resolves.toBe(true);
    await expect(store.consume("abc", Date.now())).resolves.toBe(false);
    expect(setMock).toHaveBeenNthCalledWith(1, "nonce:abc", expect.any(String), "PX", 10_000, "NX");
  });

  it("propagates redis errors to caller", async () => {
    const setMock = vi
      .fn<RedisNonceClient["set"]>()
      .mockRejectedValueOnce(new Error("redis unavailable"));

    const store = new RedisNonceStore({ set: setMock }, 10_000, "nonce:");
    await expect(store.consume("abc", Date.now())).rejects.toThrow("redis unavailable");
  });
});

