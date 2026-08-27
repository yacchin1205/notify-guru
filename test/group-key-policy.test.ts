import { describe, expect, it } from "vitest";
import {
  latestGroupKeyMatchesMembers,
  nextGroupKeyIsRecreated,
  selectUsableGroupKey,
} from "../web/group-key-policy.js";

describe("group key selection", () => {
  it("does not revive an exact member key from before the latest recreated boundary", () => {
    const state = groupState(
      ["a", "b"],
      [
        key(10, true, ["a", "b"]),
        key(20, true, ["a"]),
      ],
    );

    expect(selectUsableGroupKey(state)?.timestamp).toBe(20);
    expect(latestGroupKeyMatchesMembers(state)).toBe(false);
    expect(nextGroupKeyIsRecreated(state)).toBe(false);
  });

  it("selects the latest key whose members are all still active", () => {
    const state = groupState(
      ["a", "b"],
      [
        key(10, true, ["a"]),
        key(20, false, ["a", "b"]),
        key(30, false, ["a", "b", "c"]),
      ],
    );

    expect(selectUsableGroupKey(state)?.timestamp).toBe(20);
    expect(latestGroupKeyMatchesMembers(state)).toBe(false);
    expect(nextGroupKeyIsRecreated(state)).toBe(true);
  });

  it("creates a recreated boundary after a device was removed even when an older key is usable", () => {
    const state = groupState(
      ["a"],
      [
        key(10, true, ["a"]),
        key(20, false, ["a", "b"]),
      ],
    );

    expect(selectUsableGroupKey(state)?.timestamp).toBe(10);
    expect(latestGroupKeyMatchesMembers(state)).toBe(false);
    expect(nextGroupKeyIsRecreated(state)).toBe(true);
  });
});

function groupState(deviceIds: string[], keys: ReturnType<typeof key>[]) {
  return {
    members: deviceIds.map((deviceId) => ({ deviceId })),
    keys,
  };
}

function key(timestamp: number, recreated: boolean, members: string[]) {
  return { timestamp, recreated, members };
}
