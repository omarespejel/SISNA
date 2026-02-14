import { RateLimiterUnavailableError, type RateLimiter, type RateLimitDecision } from "./rateLimiter.js";

export type RedisRateLimitClient = {
  incr(key: string): Promise<number>;
  pexpire(key: string, ttlMs: number): Promise<number>;
};

export class RedisRateLimiter implements RateLimiter {
  constructor(
    private readonly redis: RedisRateLimitClient,
    private readonly windowMs: number,
    private readonly maxRequests: number,
    private readonly keyPrefix: string,
  ) {}

  async check(key: string, nowMs: number): Promise<RateLimitDecision> {
    try {
      const bucketId = Math.floor(nowMs / this.windowMs);
      const resetAtMs = (bucketId + 1) * this.windowMs;
      const redisKey = `${this.keyPrefix}${bucketId}:${key}`;

      const count = await this.redis.incr(redisKey);
      if (count === 1) {
        await this.redis.pexpire(redisKey, this.windowMs * 2);
      }

      const allowed = count <= this.maxRequests;
      const remaining = Math.max(0, this.maxRequests - count);

      return {
        allowed,
        remaining,
        resetAtMs,
      };
    } catch (err) {
      throw new RateLimiterUnavailableError(
        err instanceof Error ? err.message : String(err),
      );
    }
  }
}
