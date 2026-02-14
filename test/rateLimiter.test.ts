import { describe, expect, it } from "vitest";
import { InMemoryRateLimiter } from "../src/security/rateLimiter.js";

describe("in-memory rate limiter", () => {
  it("allows up to max requests in window and blocks after", () => {
    const rl = new InMemoryRateLimiter(10_000, 2);
    const now = 1_000;

    const first = rl.check("client:a", now);
    const second = rl.check("client:a", now + 1);
    const third = rl.check("client:a", now + 2);

    expect(first.allowed).toBe(true);
    expect(second.allowed).toBe(true);
    expect(third.allowed).toBe(false);
    expect(third.remaining).toBe(0);
  });

  it("resets budget after window", () => {
    const rl = new InMemoryRateLimiter(5_000, 1);
    const first = rl.check("client:b", 1_000);
    const blocked = rl.check("client:b", 1_100);
    const reset = rl.check("client:b", 7_000);

    expect(first.allowed).toBe(true);
    expect(blocked.allowed).toBe(false);
    expect(reset.allowed).toBe(true);
  });
});
