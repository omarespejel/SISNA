export interface NonceStore {
  consume(nonce: string, nowMs: number): boolean | Promise<boolean>;
}

export class InMemoryNonceStore implements NonceStore {
  private readonly seen = new Map<string, number>();

  constructor(private readonly ttlMs: number) {}

  consume(nonce: string, nowMs: number): boolean {
    this.gc(nowMs);

    const exp = this.seen.get(nonce);
    if (exp && exp > nowMs) {
      return false;
    }

    this.seen.set(nonce, nowMs + this.ttlMs);
    return true;
  }

  private gc(nowMs: number): void {
    for (const [nonce, exp] of this.seen.entries()) {
      if (exp <= nowMs) {
        this.seen.delete(nonce);
      }
    }
  }
}
