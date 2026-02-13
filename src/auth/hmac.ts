import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

export function buildSigningPayload(args: {
  timestamp: string;
  nonce: string;
  method: string;
  path: string;
  rawBody: string;
}): string {
  const bodyHash = sha256Hex(args.rawBody);
  return `${args.timestamp}.${args.nonce}.${args.method.toUpperCase()}.${args.path}.${bodyHash}`;
}

export function computeHmacHex(secret: string, payload: string): string {
  return createHmac("sha256", secret).update(payload).digest("hex");
}

export function secureHexEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, "hex");
  const right = Buffer.from(b, "hex");
  if (left.length !== right.length) {
    return false;
  }
  return timingSafeEqual(left, right);
}
