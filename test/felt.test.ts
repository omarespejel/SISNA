import { describe, expect, it } from "vitest";
import { normalizeFelt } from "../src/utils/felt.js";

describe("normalizeFelt", () => {
  it("normalizes decimal and hex values to lowercase 0x format", () => {
    expect(normalizeFelt("26")).toBe("0x1a");
    expect(normalizeFelt("0x1A")).toBe("0x1a");
  });

  it("rejects negative values", () => {
    expect(() => normalizeFelt("-1")).toThrow(/invalid felt value/i);
  });

  it("rejects invalid numeric strings", () => {
    expect(() => normalizeFelt("not-a-number")).toThrow(/invalid felt value/i);
    expect(() => normalizeFelt("")).toThrow(/invalid felt value/i);
  });
});
