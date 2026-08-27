import { describe, expect, it } from "vitest";
import {
  createDeviceIdentity,
  createGroupKey,
  createKeyPackage,
  deviceCreateTranscript,
  groupKeyRegisterTranscript,
  groupCreateTranscript,
  openKeyPackage,
  signDevice,
} from "../web/crypto.js";
import { verifyP256Signature } from "../src/protocol";

describe("web device-group cryptography", () => {
  it("keeps an in-progress device request out of the saved identity", async () => {
    expect(await createDeviceIdentity()).not.toHaveProperty("deviceRequest");
  });

  it("wraps a group private key for exactly one registered device", async () => {
    const device = await registeredIdentity("device_identifier_1234");
    const other = await registeredIdentity("other_device_identifier");
    const groupKey = await createGroupKey();
    const keyPackage = await createKeyPackage("group_identifier_1234", groupKey, device);
    const keyRecord = { timestamp: 1_789_999_000_001, publicKey: groupKey.publicKey };
    const envelope = { timestamp: keyRecord.timestamp, ...keyPackage };
    await expect(openKeyPackage(device, "group_identifier_1234", keyRecord, envelope)).resolves.toEqual({
      ...groupKey,
      timestamp: keyRecord.timestamp,
    });
    await expect(openKeyPackage(other, "group_identifier_1234", keyRecord, envelope)).rejects.toThrow();
  });

  it("binds a key package to its group public key and recipient", async () => {
    const device = await registeredIdentity("device_identifier_1234");
    const groupKey = await createGroupKey();
    const keyPackage = await createKeyPackage("group_identifier_1234", groupKey, device);
    const otherKey = await createGroupKey();
    await expect(openKeyPackage(device, "group_identifier_1234", {
      timestamp: 1_789_999_000_001,
      publicKey: otherKey.publicKey,
    }, { timestamp: 1_789_999_000_001, ...keyPackage })).rejects.toThrow();
  });

  it("creates signatures accepted for device registration and group creation", async () => {
    const device = await registeredIdentity("device_identifier_1234");
    const nonce = "nonce_identifier_1234";
    const createDevice = deviceCreateTranscript(device.signingPublicKey, nonce);
    expect(await verifyP256Signature(device.signingPublicKey, await signDevice(device, createDevice), createDevice)).toBe(true);

    const createGroup = groupCreateTranscript("group_identifier_1234", device, "a".repeat(64));
    expect(await verifyP256Signature(device.signingPublicKey, await signDevice(device, createGroup), createGroup)).toBe(true);
  });

  it("canonicalizes every group key package into the management signature", () => {
    const body = {
      publicKey: "group-key",
      recreated: true,
      members: ["device_b", "device_a"],
      packages: [
        { deviceId: "device_b", ephemeralPublicKey: "ephemeral-b", nonce: "nonce-b", ciphertext: "cipher-b" },
        { deviceId: "device_a", ephemeralPublicKey: "ephemeral-a", nonce: "nonce-a", ciphertext: "cipher-a" },
      ],
    };
    expect(groupKeyRegisterTranscript("group", "actor", body)).toBe([
      "notify.guru/group-key-register/v1", "group", "actor", "group-key", "1", "2",
      "device_a", "device_b", "2",
      "device_a", "ephemeral-a", "nonce-a", "cipher-a",
      "device_b", "ephemeral-b", "nonce-b", "cipher-b",
    ].join("\n"));
  });
});

async function registeredIdentity(deviceId: string) {
  const identity = await createDeviceIdentity();
  identity.deviceId = deviceId;
  return identity;
}
