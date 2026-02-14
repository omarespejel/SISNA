export interface NonceStore {
  consume(nonce: string, nowMs: number): boolean | Promise<boolean>;
}

export class InMemoryNonceStore implements NonceStore {
  private readonly seen = new Map<string, number>();
  private operationsSinceGc = 0;
  private static readonly GC_INTERVAL = 64;

  constructor(private readonly ttlMs: number) {}

  consume(nonce: string, nowMs: number): boolean {
    this.maybeGc(nowMs);

    const exp = this.seen.get(nonce);
    if (exp && exp > nowMs) {
      return false;
    }

    this.seen.set(nonce, nowMs + this.ttlMs);
    return true;
  }

  private maybeGc(nowMs: number): void {
    this.operationsSinceGc += 1;
    if (this.operationsSinceGc < InMemoryNonceStore.GC_INTERVAL) {
      return;
    }
    this.operationsSinceGc = 0;
    this.gc(nowMs);
  }

  private gc(nowMs: number): void {
    for (const [nonce, exp] of this.seen.entries()) {
      if (exp <= nowMs) {
        this.seen.delete(nonce);
      }
    }
  }
}
