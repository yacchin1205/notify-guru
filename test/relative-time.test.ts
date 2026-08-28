import { describe, expect, it } from "vitest";
import { relativeTime } from "../web/relative-time.js";

describe("relative time", () => {
  const now = 2_000_000_000_000;

  it("uses compact seconds, minutes, hours, and days", () => {
    expect(relativeTime(now - 2_000, now)).toBe("2s ago");
    expect(relativeTime(now - 20 * 60_000, now)).toBe("20m ago");
    expect(relativeTime(now - 3 * 3_600_000, now)).toBe("3h ago");
    expect(relativeTime(now - 2 * 86_400_000, now)).toBe("2d ago");
  });

  it("does not show a negative age for future timestamps", () => {
    expect(relativeTime(now + 1_000, now)).toBe("0s ago");
  });
});
