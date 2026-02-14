import type { AuditLogger } from "../audit/logger.js";

export type LeakScannerAction = "block" | "warn";
export type LeakScannerDirection = "inbound" | "outbound";

type Pattern = {
  id: string;
  regex: RegExp;
};

const DEFAULT_PATTERNS: Pattern[] = [
  { id: "env.starknet_private_key", regex: /\bSTARKNET_PRIVATE_KEY\b/i },
  { id: "env.session_private_key", regex: /\bSESSION_PRIVATE_KEY\b/i },
  { id: "env.keyring_hmac_secret", regex: /\bKEYRING_HMAC_SECRET\b/i },
  { id: "json.private_key", regex: /"private(?:_|)key"\s*:\s*"0x[0-9a-fA-F]{1,64}"/i },
  { id: "kv.private_key", regex: /\bprivate(?:_|)key\s*[:=]\s*["']?0x[0-9a-fA-F]{1,64}["']?/i },
  { id: "pem.private_key", regex: /-----BEGIN(?: EC| RSA)? PRIVATE KEY-----/i },
];

export type LeakScanResult = {
  blocked: boolean;
  patternIds: string[];
};

export class LeakScanner {
  constructor(
    private readonly enabled: boolean,
    private readonly action: LeakScannerAction,
    private readonly logger: AuditLogger,
    private readonly patterns: Pattern[] = DEFAULT_PATTERNS,
  ) {}

  scan(
    direction: LeakScannerDirection,
    text: string,
    requestId?: string,
  ): LeakScanResult {
    if (!this.enabled || !text) {
      return { blocked: false, patternIds: [] };
    }

    const patternIds: string[] = [];
    for (const pattern of this.patterns) {
      if (pattern.regex.test(text)) {
        patternIds.push(pattern.id);
      }
    }

    if (patternIds.length === 0) {
      return { blocked: false, patternIds };
    }

    this.logger.log({
      level: this.action === "block" ? "warn" : "info",
      event: "security.leak_pattern_detected",
      requestId,
      details: {
        direction,
        action: this.action,
        patternIds,
      },
    });

    return {
      blocked: this.action === "block",
      patternIds,
    };
  }
}
