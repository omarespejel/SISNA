export type RateLimitDecision = {
  allowed: boolean;
  remaining: number;
  resetAtMs: number;
};

export interface RateLimiter {
  check(key: string, nowMs: number): Promise<RateLimitDecision> | RateLimitDecision;
}

export class RateLimiterUnavailableError extends Error {
  constructor(message = "rate limiter unavailable") {
    super(message);
    this.name = "RateLimiterUnavailableError";
  }
}

type Bucket = {
  count: number;
  resetAtMs: number;
};

export class InMemoryRateLimiter implements RateLimiter {
  private readonly buckets = new Map<string, Bucket>();
  private operationsSincePrune = 0;
  private static readonly PRUNE_INTERVAL = 64;

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

    this.maybePrune(nowMs);
    return {
      allowed,
      remaining,
      resetAtMs: bucket.resetAtMs,
    };
  }

  private maybePrune(nowMs: number): void {
    this.operationsSincePrune += 1;
    if (this.operationsSincePrune < InMemoryRateLimiter.PRUNE_INTERVAL) {
      return;
    }
    this.operationsSincePrune = 0;
    this.prune(nowMs);
  }

  private prune(nowMs: number): void {
    for (const [key, bucket] of this.buckets.entries()) {
      if (bucket.resetAtMs <= nowMs) {
        this.buckets.delete(key);
      }
    }
  }
}
