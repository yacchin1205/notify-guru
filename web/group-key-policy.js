export function selectUsableGroupKey(state) {
  const active = new Set(state.members.map((member) => member.deviceId));
  const recreated = state.keys.filter((key) => key.recreated).at(-1);
  const cutoff = recreated?.timestamp ?? 0;
  return [...state.keys].reverse().find(
    (key) => key.timestamp >= cutoff && key.members.every((deviceId) => active.has(deviceId)),
  ) ?? null;
}

export function latestGroupKeyMatchesMembers(state) {
  const latest = state.keys.at(-1);
  if (latest === undefined) return false;
  const active = state.members.map((member) => member.deviceId).sort();
  return sameStrings([...latest.members].sort(), active);
}

export function nextGroupKeyIsRecreated(state) {
  const latest = state.keys.at(-1);
  if (latest === undefined) return true;
  const active = new Set(state.members.map((member) => member.deviceId));
  return latest.members.some((deviceId) => !active.has(deviceId));
}

function sameStrings(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}
