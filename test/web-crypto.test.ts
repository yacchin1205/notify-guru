import { describe, expect, it } from "vitest";
import {
  authenticatedInheritedSessions,
  authenticateInheritedSession,
  createDeviceIdentity,
  createGroupKey,
  createGroupTransition,
  createSessionDescriptor,
  createKeyPackage,
  deviceApprovalProof,
  deviceRequestBindingHash,
  deviceCreateTranscript,
  encryptAttachment,
  groupKeyRegisterTranscript,
  groupCreateTranscript,
  groupTransitionHash,
  openKeyPackage,
  signDevice,
  validateGroupTransitions,
  verifyDeviceApprovalProof,
  verifySessionDescriptor,
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

  it("rejects relay-injected keys, modified membership, and transition rollback", async () => {
    const device = await registeredIdentity("device_identifier_1234");
    const member = {
      deviceId: device.deviceId,
      signingPublicKey: device.signingPublicKey,
      encryptionPublicKey: device.encryptionPublicKey,
    };
    const firstKey = await createGroupKey();
    const firstPackages = [await createKeyPackage("group_identifier_1234", firstKey, member)];
    const first = await createGroupTransition(
      "group_identifier_1234", device, firstKey, null, [member], firstPackages, true,
    );
    device.group = {
      groupId: "group_identifier_1234",
      headTransitionHash: first.transitionHash,
      keys: { [String(first.timestamp)]: { ...firstKey, timestamp: first.timestamp, transitionHash: first.transitionHash } },
    };
    const secondKey = await createGroupKey();
    const secondPackages = [await createKeyPackage("group_identifier_1234", secondKey, member)];
    const second = await createGroupTransition(
      "group_identifier_1234", device, secondKey, first, [member], secondPackages, false,
    );
    await expect(validateGroupTransitions(
      "group_identifier_1234", [first, second], first.transitionHash,
    )).resolves.toEqual(second);

    const injected = { ...second, continuitySignature: await signDevice(device, "relay forgery") };
    injected.transitionHash = await groupTransitionHash(
      "group_identifier_1234", injected, injected.actorSignature, injected.continuitySignature,
    );
    await expect(validateGroupTransitions(
      "group_identifier_1234", [first, injected], first.transitionHash,
    )).rejects.toThrow("continuity signature");

    const changed = { ...second, members: [{ ...member, encryptionPublicKey: (await createGroupKey()).publicKey }] };
    await expect(validateGroupTransitions(
      "group_identifier_1234", [first, changed], first.transitionHash,
    )).rejects.toThrow("hash");
    await expect(validateGroupTransitions(
      "group_identifier_1234", [first], second.transitionHash,
    )).rejects.toThrow("trusted group transition is missing");
  });

  it("rejects a recreated self-removal and keeps signature malleation on the same transition hash", async () => {
    const leaving = await registeredIdentity("leaving_device_identifier");
    const remaining = await registeredIdentity("remaining_device_identifier");
    const members = [leaving, remaining].map((device) => ({
      deviceId: device.deviceId, signingPublicKey: device.signingPublicKey,
      encryptionPublicKey: device.encryptionPublicKey,
    }));
    const firstKey = await createGroupKey();
    const firstPackages = await Promise.all(members.map((member) =>
      createKeyPackage("group_identifier_1234", firstKey, member)));
    const first = await createGroupTransition(
      "group_identifier_1234", leaving, firstKey, null, members, firstPackages, true,
    );
    leaving.group = {
      groupId: "group_identifier_1234", headTransitionHash: first.transitionHash,
      keys: { [String(first.timestamp)]: { ...firstKey, timestamp: first.timestamp, transitionHash: first.transitionHash } },
    };
    const attackerKnownKey = await createGroupKey();
    const remainingMember = members[1];
    const forged = await createGroupTransition(
      "group_identifier_1234", leaving, attackerKnownKey, first, [remainingMember],
      [await createKeyPackage("group_identifier_1234", attackerKnownKey, remainingMember)], true,
    );
    await expect(validateGroupTransitions(
      "group_identifier_1234", [first, forged], first.transitionHash,
    )).rejects.toThrow("self-removal");

    const malleated = { ...first, actorSignature: malleateP256Signature(first.actorSignature) };
    expect(await groupTransitionHash(
      "group_identifier_1234", malleated, malleated.actorSignature, malleated.continuitySignature,
    )).toBe(first.transitionHash);
    await expect(validateGroupTransitions(
      "group_identifier_1234", [malleated], first.transitionHash,
    )).resolves.toEqual(malleated);
  });

  it("authenticates inherited session descriptors with device and group continuity keys", async () => {
    const identity = await registeredIdentity("device_identifier_1234");
    const member = {
      deviceId: identity.deviceId, signingPublicKey: identity.signingPublicKey,
      encryptionPublicKey: identity.encryptionPublicKey,
    };
    const key = await createGroupKey();
    const transition = await createGroupTransition(
      "group_identifier_1234", identity, key, null, [member],
      [await createKeyPackage("group_identifier_1234", key, member)], true,
    );
    const localKey = { ...key, timestamp: transition.timestamp, transitionHash: transition.transitionHash };
    const descriptor = await createSessionDescriptor(
      identity, localKey, "session_identifier_1234", "group_identifier_1234", key.publicKey,
    );
    const invalidCurvePoint = base64url(new Uint8Array(65));
    await expect(createSessionDescriptor(
      identity, localKey, "invalid_key_session", "group_identifier_1234", invalidCurvePoint,
    )).rejects.toThrow();
    expect(await verifySessionDescriptor(descriptor, "group_identifier_1234", [transition])).toBe(true);
    expect(await verifySessionDescriptor(
      { ...descriptor, creatorPublicKey: invalidCurvePoint }, "group_identifier_1234", [transition],
    )).toBe(false);
    await expect(authenticateInheritedSession(
      descriptor, "group_identifier_1234", [transition],
    )).resolves.toBeUndefined();
    await expect(authenticateInheritedSession(
      { ...descriptor, creatorPublicKey: (await createGroupKey()).publicKey },
      "group_identifier_1234", [transition],
    )).rejects.toThrow("unauthenticated session descriptor");
    await expect(authenticateInheritedSession(
      { ...descriptor, protocolVersion: 3 },
      "group_identifier_1234", [transition],
    )).rejects.toThrow("unauthenticated session descriptor");
    const legacy = {
      ...descriptor, sessionId: "legacy_session_identifier", protocolVersion: 3,
      keyTimestamp: null, transitionHash: null, actorDeviceId: null,
      actorSignature: null, continuitySignature: null,
    };
    await expect(authenticatedInheritedSessions(
      [legacy, descriptor], "group_identifier_1234", [transition],
    )).resolves.toEqual([descriptor]);
    await expect(authenticatedInheritedSessions(
      [legacy, { ...descriptor, creatorPublicKey: (await createGroupKey()).publicKey }],
      "group_identifier_1234", [transition],
    )).resolves.toEqual([]);
  });

  it("rejects session descriptors signed by a device removed from the current head", async () => {
    const groupId = "group_identifier_1234";
    const removed = await registeredIdentity("removed_device_identifier");
    const remaining = await registeredIdentity("remaining_device_identifier");
    const removedMember = {
      deviceId: removed.deviceId, signingPublicKey: removed.signingPublicKey,
      encryptionPublicKey: removed.encryptionPublicKey,
    };
    const remainingMember = {
      deviceId: remaining.deviceId, signingPublicKey: remaining.signingPublicKey,
      encryptionPublicKey: remaining.encryptionPublicKey,
    };
    const initialDraft = await createGroupKey();
    const initial = await createGroupTransition(
      groupId, removed, initialDraft, null, [removedMember, remainingMember],
      await Promise.all([
        createKeyPackage(groupId, initialDraft, removedMember),
        createKeyPackage(groupId, initialDraft, remainingMember),
      ]), true,
    );
    const initialKey = {
      ...initialDraft, timestamp: initial.timestamp, transitionHash: initial.transitionHash,
    };
    remaining.group = { groupId, keys: { [String(initial.timestamp)]: initialKey } };
    const removedDescriptor = await createSessionDescriptor(
      removed, initialKey, "removed_actor_session", groupId, initialDraft.publicKey,
    );
    const remainingDescriptor = await createSessionDescriptor(
      remaining, initialKey, "remaining_actor_session", groupId, initialDraft.publicKey,
    );
    const currentDraft = await createGroupKey();
    const current = await createGroupTransition(
      groupId, remaining, currentDraft, initial, [remainingMember],
      [await createKeyPackage(groupId, currentDraft, remainingMember)], true,
    );
    await expect(validateGroupTransitions(groupId, [initial, current], initial.transitionHash)).resolves.toEqual(current);
    await expect(verifySessionDescriptor(removedDescriptor, groupId, [initial, current])).resolves.toBe(false);
    await expect(authenticateInheritedSession(
      removedDescriptor, groupId, [initial, current],
    )).rejects.toThrow("unauthenticated session descriptor");
    await expect(verifySessionDescriptor(remainingDescriptor, groupId, [initial, current])).resolves.toBe(true);
    await expect(authenticatedInheritedSessions(
      [removedDescriptor, remainingDescriptor], groupId, [initial, current],
    )).resolves.toEqual([remainingDescriptor]);
  });

  it("binds device approval to the complete request and accepted transition", async () => {
    const device = await registeredIdentity("device_identifier_1234");
    const request = {
      requestId: "request_identifier_1234", deviceId: device.deviceId,
      signingPublicKey: device.signingPublicKey, accessHash: "a".repeat(64),
      encryptionPublicKey: device.encryptionPublicKey, protocolVersion: 4,
    };
    const binding = await deviceRequestBindingHash(request);
    expect(binding).toMatch(/^[a-f0-9]{64}$/);
    const secret = base64url(crypto.getRandomValues(new Uint8Array(32)));
    const proof = await deviceApprovalProof(secret, request.requestId, "group", "b".repeat(64));
    await expect(verifyDeviceApprovalProof(
      secret, request.requestId, "group", "b".repeat(64), proof,
    )).resolves.toBe(true);
    await expect(verifyDeviceApprovalProof(
      secret, request.requestId, "group", "c".repeat(64), proof,
    )).resolves.toBe(false);
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

  it("encrypts a version 4 attachment under its own ECDH and AAD context", async () => {
    const creator = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"],
    ) as CryptoKeyPair;
    const creatorPublic = new Uint8Array(await crypto.subtle.exportKey("raw", creator.publicKey));
    const groupKey = { ...await createGroupKey(), timestamp: 42 };
    const jpeg = { bytes: new Uint8Array([0xff, 0xd8, 0xff, 0xd9]), width: 1, height: 1 };
    const encrypted = await encryptAttachment(
      groupKey, base64url(creatorPublic), "session", "group", "response", "attachment", jpeg,
    );
    const groupPublic = await crypto.subtle.importKey(
      "raw", fromBase64url(groupKey.publicKey), { name: "ECDH", namedCurve: "P-256" }, false, [],
    );
    const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: groupPublic }, creator.privateKey, 256);
    const material = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey({
      name: "HKDF", hash: "SHA-256", salt: new Uint8Array(),
      info: new TextEncoder().encode("notify.guru/attachment/v4\nsession\ngroup\n" + groupKey.timestamp + "\nresponse\nattachment"),
    }, material, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    const plaintext = await crypto.subtle.decrypt({
      name: "AES-GCM", iv: fromBase64url(encrypted.manifest.nonce),
      additionalData: new TextEncoder().encode(
        "notify.guru/v4/attachment/session/group/" + groupKey.timestamp + "/response/attachment",
      ),
    }, key, encrypted.ciphertext);
    expect(new Uint8Array(plaintext)).toEqual(jpeg.bytes);
    expect(encrypted.manifest.ciphertextLength).toBe(jpeg.bytes.byteLength + 16);
    await expect(crypto.subtle.decrypt({
      name: "AES-GCM", iv: fromBase64url(encrypted.manifest.nonce),
      additionalData: new TextEncoder().encode(
        "notify.guru/v4/attachment/session/group/" + groupKey.timestamp + "/response/other",
      ),
    }, key, encrypted.ciphertext)).rejects.toThrow();
  });
});

async function registeredIdentity(deviceId: string) {
  const identity = await createDeviceIdentity();
  identity.deviceId = deviceId;
  return identity;
}

function base64url(value: Uint8Array): string {
  return btoa(String.fromCharCode(...value)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function fromBase64url(value: string): Uint8Array {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

function malleateP256Signature(signature: string): string {
  const bytes = fromBase64url(signature);
  const order = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
  const s = BigInt(`0x${Array.from(bytes.slice(32), (byte) => byte.toString(16).padStart(2, "0")).join("")}`);
  const replacement = (order - s).toString(16).padStart(64, "0");
  for (let index = 0; index < 32; index += 1) bytes[32 + index] = Number.parseInt(replacement.slice(index * 2, index * 2 + 2), 16);
  return base64url(bytes);
}
