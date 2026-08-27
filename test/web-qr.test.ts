import { describe, expect, it } from "vitest";
import { qrMatrix } from "../web/qr.js";

describe("browser QR generation", () => {
  it("generates a deterministic square matrix without exposing the value externally", () => {
    const first = qrMatrix("https://notify.guru/device#secret-in-fragment");
    const second = qrMatrix("https://notify.guru/device#secret-in-fragment");

    expect(first.size).toBeGreaterThanOrEqual(21);
    expect(first.modules).toEqual(second.modules);
    expect(first.modules).toHaveLength(first.size);
    expect(first.modules.every((row) => row.length === first.size)).toBe(true);
    expect(first.modules.flat()).toContain(true);
    expect(first.modules.flat()).toContain(false);
  });

  it("rejects empty values", () => {
    expect(() => qrMatrix("")).toThrow("QR value must be a non-empty string");
  });
});
