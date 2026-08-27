import { describe, expect, it } from "vitest";
import {
  createDeviceIdentity,
  createGeneration,
  createKeyPackage,
  groupCreateTranscript,
  hashPackages,
  openKeyPackage,
  signDevice,
  signGeneration,
  transitionTranscript,
  verificationCode,
  verifySignature,
} from "../web/crypto.js";

describe("web device-group cryptography", () => {
  it("wraps a generation private key for exactly one device", async () => {
    const device = await createDeviceIdentity();
    const other = await createDeviceIdentity();
    const generation = await createGeneration(7);
    const descriptor = {
      deviceId: device.deviceId,
      encryptionPublicKey: device.encryptionPublicKey,
      signingPublicKey: device.signingPublicKey,
    };
    const keyPackage = await createKeyPackage("group_identifier_1234", generation, descriptor);
    const opened = await openKeyPackage(device, "group_identifier_1234", generation.publicKey, keyPackage);
    expect(opened).toEqual(generation);
    await expect(openKeyPackage(other, "group_identifier_1234", generation.publicKey, keyPackage)).rejects.toThrow();
  });

  it("creates signatures accepted by both device and generation public keys", async () => {
    const device = await createDeviceIdentity();
    const generation = await createGeneration(1);
    const keyPackage = await createKeyPackage("group_identifier_1234", generation, {
      deviceId: device.deviceId,
      encryptionPublicKey: device.encryptionPublicKey,
      signingPublicKey: device.signingPublicKey,
    });
    const packagesHash = await hashPackages([keyPackage]);
    const create = groupCreateTranscript("group_identifier_1234", device, generation, packagesHash);
    expect(await verifySignature(device.signingPublicKey, await signDevice(device, create), create)).toBe(true);

    const transition = {
      revision: 2,
      previousGeneration: 1,
      generation: 2,
      generationPublicKey: (await createGeneration(2)).publicKey,
      action: "remove",
      actorDeviceId: device.deviceId,
      targetDeviceId: "target_device_identifier",
      packagesHash,
    };
    const transcript = transitionTranscript("group_identifier_1234", transition);
    expect(await verifySignature(generation.publicKey, await signGeneration(generation, transcript), transcript)).toBe(true);
  });

  it("shows the same verification code for the invitation and pending device", async () => {
    const device = await createDeviceIdentity();
    const invitation = {
      groupId: "group_identifier_1234",
      invitationId: "invitation_identifier",
      invitationToken: "invitation_token_value",
    };
    const pending = {
      deviceId: device.deviceId,
      encryptionPublicKey: device.encryptionPublicKey,
      signingPublicKey: device.signingPublicKey,
    };
    expect(await verificationCode(invitation, pending)).toMatch(/^\d{6}$/);
    expect(await verificationCode(invitation, pending)).toBe(await verificationCode(invitation, pending));
  });
});
