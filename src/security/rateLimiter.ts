export type RateLimitDecision = {
  allowed: boolean;
  remaining: number;
  resetAtMs: number;
};

export interface RateLimiter {
  check(key: string, nowMs: number): Promise<RateLimitDecision> | RateLimitDecision;
}

type Bucket = {
  count: number;
  resetAtMs: number;
};

export class InMemoryRateLimiter implements RateLimiter {
  private readonly buckets = new Map<string, Bucket>();

  constructor(
    private readonly windowMs: number,
    private readonly maxRequests: number,
  ) {}

  check(key: string, nowMs: number): RateLimitDecision {
    const current = this.buckets.get(key);
    const bucket = (!current || current.resetAtMs <= nowMs)
      ? { count: 0, resetAtMs: nowMs + this.windowMs }
      : current;

    bucket.count += 1;
    this.buckets.set(key, bucket);

    const allowed = bucket.count <= this.maxRequests;
    const remaining = Math.max(0, this.maxRequests - bucket.count);

    this.prune(nowMs);
    return {
      allowed,
      remaining,
      resetAtMs: bucket.resetAtMs,
    };
  }

  private prune(nowMs: number): void {
    for (const [key, bucket] of this.buckets.entries()) {
      if (bucket.resetAtMs <= nowMs) {
        this.buckets.delete(key);
      }
    }
  }
}
