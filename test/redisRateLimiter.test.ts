import { describe, expect, it } from "vitest";
import { RedisRateLimiter } from "../src/security/redisRateLimiter.js";
import { RateLimiterUnavailableError } from "../src/security/rateLimiter.js";

class MockRedis {
  private readonly counters = new Map<string, number>();

  async incr(key: string): Promise<number> {
    const next = (this.counters.get(key) ?? 0) + 1;
    this.counters.set(key, next);
    return next;
  }

  async pexpire(_key: string, _ttlMs: number): Promise<number> {
    return 1;
  }
}

class FailingRedis {
  async incr(_key: string): Promise<number> {
    throw new Error("redis offline");
  }

  async pexpire(_key: string, _ttlMs: number): Promise<number> {
    return 1;
  }
}

describe("redis rate limiter", () => {
  it("uses shared counters and blocks after max", async () => {
    const redis = new MockRedis();
    const limiter = new RedisRateLimiter(redis, 10_000, 2, "ratelimit:");

    const first = await limiter.check("client:a", 1_000);
    const second = await limiter.check("client:a", 1_100);
    const third = await limiter.check("client:a", 1_200);

    expect(first.allowed).toBe(true);
    expect(second.allowed).toBe(true);
    expect(third.allowed).toBe(false);
    expect(third.remaining).toBe(0);
  });

  it("throws unavailable error when redis backend fails", async () => {
    const limiter = new RedisRateLimiter(new FailingRedis(), 10_000, 2, "ratelimit:");
    await expect(limiter.check("client:a", 1_000)).rejects.toBeInstanceOf(RateLimiterUnavailableError);
  });
});
