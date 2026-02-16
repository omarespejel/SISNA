import { describe, expect, it } from "vitest";
import { normalizeFelt } from "../src/utils/felt.js";

describe("normalizeFelt", () => {
  it("normalizes decimal and hex values to lowercase 0x format", () => {
    expect(normalizeFelt("26")).toBe("0x1a");
    expect(normalizeFelt("0x1A")).toBe("0x1a");
  });

  it("normalizes zero correctly", () => {
    expect(normalizeFelt("0")).toBe("0x0");
    expect(normalizeFelt("0x0")).toBe("0x0");
  });

  it("handles whitespace and leading zeros", () => {
    expect(normalizeFelt("  26  ")).toBe("0x1a");
    expect(normalizeFelt("0x001A")).toBe("0x1a");
  });

  it("rejects negative values", () => {
    expect(() => normalizeFelt("-1")).toThrow(/invalid felt value/i);
  });

  it("rejects invalid numeric strings", () => {
    expect(() => normalizeFelt("not-a-number")).toThrow(/invalid felt value/i);
    expect(() => normalizeFelt("")).toThrow(/invalid felt value/i);
  });

  it("rejects values outside felt252 field range", () => {
    expect(() => normalizeFelt("0x800000000000011000000000000000000000000000000000000000000000001"))
      .toThrow(/invalid felt value/i);
  });
});
