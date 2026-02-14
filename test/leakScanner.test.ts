import { describe, expect, it } from "vitest";
import { AuditLogger } from "../src/audit/logger.js";
import { LeakScanner } from "../src/security/leakScanner.js";

describe("leak scanner", () => {
  it("blocks when configured to block and pattern matches", () => {
    const scanner = new LeakScanner(true, "block", new AuditLogger("error"));
    const result = scanner.scan("inbound", '{"privateKey":"0x1234"}');
    expect(result.blocked).toBe(true);
    expect(result.patternIds.length).toBeGreaterThan(0);
  });

  it("warn mode detects but does not block", () => {
    const scanner = new LeakScanner(true, "warn", new AuditLogger("error"));
    const result = scanner.scan("inbound", "STARKNET_PRIVATE_KEY=0x1234");
    expect(result.blocked).toBe(false);
    expect(result.patternIds).toContain("env.starknet_private_key");
  });

  it("does not flag normal signing response payload", () => {
    const scanner = new LeakScanner(true, "block", new AuditLogger("error"));
    const result = scanner.scan(
      "outbound",
      JSON.stringify({
        signature: [
          "0x1",
          "0x2",
          "0x3",
          "0x4",
        ],
      }),
    );
    expect(result.blocked).toBe(false);
    expect(result.patternIds).toHaveLength(0);
  });
});
