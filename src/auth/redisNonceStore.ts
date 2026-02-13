import type { NonceStore } from "./nonceStore.js";

export interface RedisNonceClient {
  set(
    key: string,
    value: string,
    mode: "PX",
    durationMs: number,
    condition: "NX",
  ): Promise<"OK" | null>;
}

export class RedisNonceStore implements NonceStore {
  constructor(
    private readonly redis: RedisNonceClient,
    private readonly ttlMs: number,
    private readonly keyPrefix: string,
  ) {}

  async consume(nonce: string, nowMs: number): Promise<boolean> {
    const key = `${this.keyPrefix}${nonce}`;
    const result = await this.redis.set(key, String(nowMs), "PX", this.ttlMs, "NX");
    return result === "OK";
  }
}

