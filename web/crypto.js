const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export async function createDeviceIdentity() {
  const encryptionKeyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"],
  );
  const signingKeyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
  );
  return {
    protocolVersion: 4,
    deviceId: null,
    accessToken: randomToken(),
    encryptionKeyPair,
    encryptionPublicKey: encode(await crypto.subtle.exportKey("raw", encryptionKeyPair.publicKey)),
    signingKeyPair,
    signingPublicKey: encode(await crypto.subtle.exportKey("raw", signingKeyPair.publicKey)),
    group: null,
  };
}

export async function createGroupKey() {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"],
  );
  const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  if (typeof jwk.d !== "string") throw new Error("Generated P-256 key did not contain private material");
  return {
    publicKey: encode(await crypto.subtle.exportKey("raw", pair.publicKey)),
    privateKey: jwk.d,
  };
}

export async function createKeyPackage(groupId, groupKey, device) {
  const ephemeral = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"],
  );
  const recipient = await importPublic(device.encryptionPublicKey, "ECDH");
  const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: recipient }, ephemeral.privateKey, 256);
  const context = packageContext(groupId, groupKey.publicKey, device.deviceId);
  const key = await hkdfKey(shared, context);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: encoder.encode(context) },
    key,
    encoder.encode(["notify.guru/group-key/v2", groupKey.publicKey, groupKey.privateKey].join("\n")),
  );
  return {
    deviceId: device.deviceId,
    ephemeralPublicKey: encode(await crypto.subtle.exportKey("raw", ephemeral.publicKey)),
    nonce: encode(nonce),
    ciphertext: encode(ciphertext),
  };
}

export async function openKeyPackage(identity, groupId, keyRecord, keyPackage) {
  if (keyPackage.deviceId !== identity.deviceId) throw new Error("Key package targets another device");
  if (keyPackage.timestamp !== keyRecord.timestamp) throw new Error("Key package timestamp does not match its key");
  const ephemeral = await importPublic(keyPackage.ephemeralPublicKey, "ECDH");
  const shared = await crypto.subtle.deriveBits(
    { name: "ECDH", public: ephemeral }, identity.encryptionKeyPair.privateKey, 256,
  );
  const context = packageContext(groupId, keyRecord.publicKey, identity.deviceId);
  const key = await hkdfKey(shared, context);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: decode(keyPackage.nonce), additionalData: encoder.encode(context) },
    key,
    decode(keyPackage.ciphertext),
  );
  const fields = decoder.decode(plaintext).split("\n");
  if (fields.length !== 3 || fields[0] !== "notify.guru/group-key/v2" || fields[1] !== keyRecord.publicKey) {
    throw new Error("Key package contains an invalid group key");
  }
  const groupKey = { timestamp: keyRecord.timestamp, publicKey: fields[1], privateKey: fields[2] };
  await groupPrivateKey(groupKey, "ECDH", ["deriveBits"]);
  return groupKey;
}

export async function deriveSessionKey(groupKey, creatorPublicKey, sessionId, groupId, protocolVersion = 3) {
  const privateKey = await groupPrivateKey(groupKey, "ECDH", ["deriveBits"]);
  const publicKey = await importPublic(creatorPublicKey, "ECDH");
  const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256);
  return hkdfKey(shared, `notify.guru/session/v${protocolVersion}\n${sessionId}\n${groupId}\n${groupKey.timestamp}`);
}

export async function pairingProof(
  authSecret, protocolVersion, sessionId, pairingId, groupId, timestamp, groupPublicKey, transitionHash,
) {
  const key = await crypto.subtle.importKey(
    "raw", decode(authSecret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const transcript = [
    `v${protocolVersion}`, sessionId, pairingId, groupId, String(timestamp), groupPublicKey,
    ...(protocolVersion === 4 ? [transitionHash] : []),
  ].join("\n");
  return encode(await crypto.subtle.sign("HMAC", key, encoder.encode(transcript)));
}

export function sessionDescriptorTranscript(descriptor) {
  return [
    "notify.guru/session-descriptor/v1", descriptor.sessionId, descriptor.groupId,
    String(descriptor.protocolVersion), descriptor.creatorPublicKey, String(descriptor.keyTimestamp),
    descriptor.transitionHash, descriptor.actorDeviceId,
  ].join("\n");
}

export async function createSessionDescriptor(identity, groupKey, sessionId, groupId, creatorPublicKey) {
  if (typeof groupKey.transitionHash !== "string" || !/^[a-f0-9]{64}$/.test(groupKey.transitionHash)) {
    throw new Error("Group key has no authenticated transition hash");
  }
  await importPublic(creatorPublicKey, "ECDH");
  const content = {
    sessionId, groupId, protocolVersion: 4, creatorPublicKey,
    keyTimestamp: groupKey.timestamp, transitionHash: groupKey.transitionHash,
    actorDeviceId: identity.deviceId,
  };
  const transcript = sessionDescriptorTranscript(content);
  return {
    ...content,
    actorSignature: await signDevice(identity, transcript),
    continuitySignature: await signGroupKey(groupKey, transcript),
  };
}

export async function verifySessionDescriptor(descriptor, groupId, transitions) {
  if (descriptor.groupId !== groupId || descriptor.protocolVersion !== 4) return false;
  try {
    await importPublic(descriptor.creatorPublicKey, "ECDH");
  } catch {
    return false;
  }
  const transition = transitions.find((item) => item.timestamp === descriptor.keyTimestamp
    && item.transitionHash === descriptor.transitionHash);
  const actor = transition?.members.find((member) => member.deviceId === descriptor.actorDeviceId);
  const currentActor = transitions.at(-1)?.members.find((member) => member.deviceId === descriptor.actorDeviceId);
  if (transition === undefined || actor === undefined || currentActor === undefined
    || currentActor.signingPublicKey !== actor.signingPublicKey
    || currentActor.encryptionPublicKey !== actor.encryptionPublicKey) return false;
  const transcript = sessionDescriptorTranscript(descriptor);
  return await verifySignature(actor.signingPublicKey, descriptor.actorSignature, transcript)
    && await verifySignature(transition.publicKey, descriptor.continuitySignature, transcript);
}

export async function authenticateInheritedSession(descriptor, groupId, transitions) {
  if (descriptor.protocolVersion !== 4
    || !await verifySessionDescriptor(descriptor, groupId, transitions)) {
    throw new Error("Relay supplied an unauthenticated session descriptor");
  }
}

export async function authenticatedInheritedSessions(sessions, groupId, transitions) {
  const authenticated = [];
  for (const descriptor of sessions) {
    if (descriptor.protocolVersion !== 4) continue;
    try {
      if (await verifySessionDescriptor(descriptor, groupId, transitions)) authenticated.push(descriptor);
    } catch {
      // A relay-controlled descriptor is rejected per session; it must not keep a
      // previously stored session active by failing the whole synchronization.
    }
  }
  return authenticated;
}

export function deviceCreateTranscript(signingPublicKey, nonce) {
  return ["notify.guru/device-create/v1", signingPublicKey, nonce].join("\n");
}

export function groupCreateTranscript(groupId, identity, accessHash) {
  return [
    "notify.guru/group-create/v2", groupId, identity.deviceId, accessHash, identity.encryptionPublicKey,
  ].join("\n");
}

export function deviceRequestTranscript(requestId, identity, accessHash, protocolVersion = 3) {
  return [
    protocolVersion === 4 ? "notify.guru/device-request/v2" : "notify.guru/device-request/v1",
    requestId, identity.deviceId, accessHash, identity.encryptionPublicKey,
    ...(protocolVersion === 4 ? ["3,4"] : []),
  ].join("\n");
}

export function deviceRequestReadTranscript(requestId, deviceId) {
  return ["notify.guru/device-request-read/v1", requestId, deviceId].join("\n");
}

export function groupKeyRegisterTranscript(groupId, actorDeviceId, body) {
  const members = [...body.members].sort();
  const packagesByDevice = new Map(body.packages.map((item) => [item.deviceId, item]));
  const packages = members.map((deviceId) => {
    const item = packagesByDevice.get(deviceId);
    if (item === undefined) throw new Error("Group key package set is incomplete");
    return item;
  });
  const lines = [
    "notify.guru/group-key-register/v1",
    groupId,
    actorDeviceId,
    body.publicKey,
    body.recreated ? "1" : "0",
    String(members.length),
    ...members,
    String(packages.length),
  ];
  for (const item of packages) lines.push(item.deviceId, item.ephemeralPublicKey, item.nonce, item.ciphertext);
  return lines.join("\n");
}

export function groupDeviceApproveTranscript(groupId, actorDeviceId, requestId) {
  return ["notify.guru/group-device-approve/v1", groupId, actorDeviceId, requestId].join("\n");
}

export function groupDeviceRemoveTranscript(groupId, actorDeviceId, deviceId) {
  return ["notify.guru/group-device-remove/v1", groupId, actorDeviceId, deviceId].join("\n");
}

export async function signDevice(identity, transcript) {
  return sign(identity.signingKeyPair.privateKey, transcript);
}

export async function createGroupTransition(groupId, identity, groupKey, previous, members, packages, recreated) {
  const packageDigests = [];
  for (const keyPackage of packages) {
    packageDigests.push({ deviceId: keyPackage.deviceId, sha256: await groupKeyPackageDigest(keyPackage) });
  }
  const transition = {
    transitionId: randomId(),
    previousHash: previous?.transitionHash ?? "0".repeat(64),
    timestamp: Math.max(Date.now(), (previous?.timestamp ?? 0) + 1),
    actorDeviceId: identity.deviceId,
    publicKey: groupKey.publicKey,
    recreated,
    members: members.map((member) => ({
      deviceId: member.deviceId,
      signingPublicKey: member.signingPublicKey,
      encryptionPublicKey: member.encryptionPublicKey,
    })),
    packageDigests,
  };
  const transcript = groupTransitionTranscript(groupId, transition);
  const actorSignature = await signDevice(identity, transcript);
  const continuityKey = previous === null
    ? groupKey
    : identity.group.keys[String(previous.timestamp)];
  if (continuityKey === undefined || continuityKey.publicKey !== (previous?.publicKey ?? groupKey.publicKey)) {
    throw new Error("Previous group private key is unavailable");
  }
  const continuitySignature = await signGroupKey(continuityKey, transcript);
  const transitionHash = await groupTransitionHash(groupId, transition, actorSignature, continuitySignature);
  return { ...transition, actorSignature, continuitySignature, transitionHash };
}

export function groupTransitionTranscript(groupId, transition) {
  const members = [...transition.members].sort((left, right) => canonicalCompare(left.deviceId, right.deviceId));
  const packages = [...transition.packageDigests].sort((left, right) => canonicalCompare(left.deviceId, right.deviceId));
  const lines = [
    "notify.guru/group-transition/v1", groupId, transition.transitionId, transition.previousHash,
    String(transition.timestamp), transition.actorDeviceId, transition.publicKey,
    transition.recreated ? "1" : "0", String(members.length),
  ];
  for (const member of members) lines.push(member.deviceId, member.signingPublicKey, member.encryptionPublicKey);
  lines.push(String(packages.length));
  for (const item of packages) lines.push(item.deviceId, item.sha256);
  return lines.join("\n");
}

export async function groupTransitionHash(groupId, transition, actorSignature, continuitySignature) {
  return sha256Text([
    "notify.guru/group-transition-hash/v2",
    groupTransitionTranscript(groupId, transition),
  ].join("\n"));
}

export async function validateGroupTransitions(groupId, transitions, trustedHash) {
  if (!Array.isArray(transitions) || transitions.length === 0) throw new Error("Group transition chain is empty");
  let previous = null;
  let trustedSeen = trustedHash === undefined;
  for (const transition of transitions) {
    const expectedPrevious = previous?.transitionHash ?? "0".repeat(64);
    if (transition.previousHash !== expectedPrevious) throw new Error("Group transition chain is not contiguous");
    if (previous !== null && transition.timestamp <= previous.timestamp) throw new Error("Group transition timestamp did not advance");
    const hash = await groupTransitionHash(
      groupId, transition, transition.actorSignature, transition.continuitySignature,
    );
    if (hash !== transition.transitionHash) throw new Error("Group transition hash is invalid");
    const actorMembers = previous?.members ?? transition.members;
    const actor = actorMembers.find((member) => member.deviceId === transition.actorDeviceId);
    if (actor === undefined) throw new Error("Group transition actor is not authorized");
    const transcript = groupTransitionTranscript(groupId, transition);
    if (!await verifySignature(actor.signingPublicKey, transition.actorSignature, transcript)) {
      throw new Error("Group transition actor signature is invalid");
    }
    if (!await verifySignature(previous?.publicKey ?? transition.publicKey, transition.continuitySignature, transcript)) {
      throw new Error("Group transition continuity signature is invalid");
    }
    const memberIds = transition.members.map((member) => member.deviceId);
    const packageIds = transition.packageDigests.map((item) => item.deviceId);
    if (new Set(memberIds).size !== memberIds.length || new Set(packageIds).size !== packageIds.length
      || transition.packageDigests.length !== transition.members.length
      || transition.packageDigests.some((item) => !transition.members.some((member) => member.deviceId === item.deviceId))) {
      throw new Error("Group transition package set is invalid");
    }
    if (previous === null && !transition.recreated) throw new Error("Genesis transition must create a fresh key");
    if (previous !== null) {
      const nextMembers = new Set(memberIds);
      const removed = previous.members.filter((member) => !nextMembers.has(member.deviceId));
      const previousById = new Map(previous.members.map((member) => [member.deviceId, member]));
      for (const member of transition.members) {
        const before = previousById.get(member.deviceId);
        if (before !== undefined && (before.signingPublicKey !== member.signingPublicKey
          || before.encryptionPublicKey !== member.encryptionPublicKey)) {
          throw new Error("A retained group member descriptor changed");
        }
      }
      const actorRemoved = removed.some((member) => member.deviceId === transition.actorDeviceId);
      if (actorRemoved && (removed.length !== 1 || transition.recreated
        || transition.publicKey !== previous.publicKey
        || transition.members.some((member) => !previousById.has(member.deviceId)))) {
        throw new Error("A self-removal must be a same-key marker removing only its actor");
      }
      if (removed.length > 0 && !actorRemoved
        && (!transition.recreated || transition.publicKey === previous.publicKey)) {
        throw new Error("Removing another device must create a fresh group key");
      }
      const previousMembers = new Set(previous.members.map((member) => member.deviceId));
      const previousWasMarker = previous.previousHash !== "0".repeat(64)
        && !previous.recreated
        && transitions.find((item) => item.transitionHash === previous.previousHash)?.members
          .some((member) => !previousMembers.has(member.deviceId));
      if (previousWasMarker && (!transition.recreated || transition.publicKey === previous.publicKey
        || memberIds.length !== previous.members.length
        || memberIds.some((id) => !previousMembers.has(id))
        || transition.members.some((member) => {
          const before = previous.members.find((item) => item.deviceId === member.deviceId);
          return before === undefined || before.signingPublicKey !== member.signingPublicKey
            || before.encryptionPublicKey !== member.encryptionPublicKey;
        }))) {
        throw new Error("A removal marker must be followed by a fresh key for the same members");
      }
    }
    if (transition.transitionHash === trustedHash) trustedSeen = true;
    previous = transition;
  }
  if (!trustedSeen) throw new Error("Previously trusted group transition is missing");
  return previous;
}

export async function verifyKeyPackageDigest(keyPackage, transition) {
  const expected = transition.packageDigests.find((item) => item.deviceId === keyPackage.deviceId);
  if (expected === undefined || expected.sha256 !== await groupKeyPackageDigest(keyPackage)) {
    throw new Error("Group key package digest is invalid");
  }
}

export async function deviceRequestBindingHash(request) {
  return sha256Text([
    "notify.guru/device-request-binding/v1",
    request.requestId,
    request.deviceId,
    request.signingPublicKey,
    request.accessHash,
    request.encryptionPublicKey,
    String(request.protocolVersion),
  ].join("\n"));
}

export async function deviceApprovalProof(authSecret, requestId, groupId, transitionHash) {
  const key = await crypto.subtle.importKey(
    "raw", decode(authSecret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const transcript = ["notify.guru/device-approval/v1", requestId, groupId, transitionHash].join("\n");
  return encode(await crypto.subtle.sign("HMAC", key, encoder.encode(transcript)));
}

export async function verifyDeviceApprovalProof(authSecret, requestId, groupId, transitionHash, proof) {
  return timingSafeEqual(
    decode(await deviceApprovalProof(authSecret, requestId, groupId, transitionHash)),
    decode(proof),
  );
}

export async function groupKeyPackageDigest(keyPackage) {
  return sha256Text([
    "notify.guru/group-key-package/v1", keyPackage.deviceId, keyPackage.ephemeralPublicKey,
    keyPackage.nonce, keyPackage.ciphertext,
  ].join("\n"));
}

export async function encryptResponse(key, protocolVersion, sessionId, groupId, timestamp, responseId, response) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: encoder.encode(responseAad(protocolVersion, sessionId, groupId, timestamp, responseId)) },
    key,
    encoder.encode(JSON.stringify(response)),
  );
  return { nonce: encode(nonce), ciphertext: encode(ciphertext) };
}

export async function decryptEvent(key, protocolVersion, sessionId, envelope) {
  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM", iv: decode(envelope.nonce),
      additionalData: encoder.encode(eventAad(protocolVersion, sessionId, envelope.groupId, envelope.keyTimestamp, envelope.eventId)),
    },
    key,
    decode(envelope.ciphertext),
  );
  return JSON.parse(decoder.decode(plaintext));
}

export async function encryptAttachment(groupKey, creatorPublicKey, sessionId, groupId, responseId, attachmentId, jpeg) {
  const privateKey = await groupPrivateKey(groupKey, "ECDH", ["deriveBits"]);
  const publicKey = await importPublic(creatorPublicKey, "ECDH");
  const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256);
  const key = await hkdfKey(
    shared,
    `notify.guru/attachment/v4\n${sessionId}\n${groupId}\n${groupKey.timestamp}\n${responseId}\n${attachmentId}`,
  );
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce,
      additionalData: encoder.encode(
        `notify.guru/v4/attachment/${sessionId}/${groupId}/${groupKey.timestamp}/${responseId}/${attachmentId}`,
      ),
    },
    key,
    jpeg.bytes,
  ));
  return {
    ciphertext,
    manifest: {
      id: attachmentId,
      kind: "image",
      mediaType: "image/jpeg",
      byteLength: jpeg.bytes.byteLength,
      width: jpeg.width,
      height: jpeg.height,
      nonce: encode(nonce),
      ciphertextLength: ciphertext.byteLength,
      ciphertextSha256: await sha256BytesHex(ciphertext),
    },
  };
}

export async function hashToken(token) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(token));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function randomToken() {
  return encode(crypto.getRandomValues(new Uint8Array(32)));
}

export function randomId() {
  return encode(crypto.getRandomValues(new Uint8Array(18)));
}

async function groupPrivateKey(groupKey, algorithm, usages) {
  const raw = decode(groupKey.publicKey);
  if (raw.length !== 65 || raw[0] !== 4) throw new Error("Invalid group public key");
  const jwk = {
    kty: "EC", crv: "P-256", x: encode(raw.slice(1, 33)), y: encode(raw.slice(33, 65)),
    d: groupKey.privateKey, ext: false,
  };
  return crypto.subtle.importKey("jwk", jwk, { name: algorithm, namedCurve: "P-256" }, false, usages);
}

async function signGroupKey(groupKey, transcript) {
  return sign(await groupPrivateKey(groupKey, "ECDSA", ["sign"]), transcript);
}

async function verifySignature(publicKey, signature, transcript) {
  const key = await importPublic(publicKey, "ECDSA");
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" }, key, decode(signature), encoder.encode(transcript),
  );
}

async function sha256Text(value) {
  return sha256BytesHex(encoder.encode(value));
}

function timingSafeEqual(left, right) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}

function canonicalCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

async function importPublic(value, algorithm) {
  return crypto.subtle.importKey(
    "raw", decode(value), { name: algorithm, namedCurve: "P-256" }, false,
    algorithm === "ECDSA" ? ["verify"] : [],
  );
}

async function hkdfKey(sharedSecret, context) {
  const material = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: encoder.encode(context) },
    material,
    { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
}

async function sign(privateKey, transcript) {
  return encode(await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, privateKey, encoder.encode(transcript),
  ));
}

function packageContext(groupId, publicKey, deviceId) {
  return `notify.guru/group-package/v2\n${groupId}\n${publicKey}\n${deviceId}`;
}

function eventAad(protocolVersion, sessionId, groupId, timestamp, eventId) {
  return `notify.guru/v${protocolVersion}/event/${sessionId}/${groupId}/${timestamp}/${eventId}`;
}

function responseAad(protocolVersion, sessionId, groupId, timestamp, responseId) {
  return `notify.guru/v${protocolVersion}/response/${sessionId}/${groupId}/${timestamp}/${responseId}`;
}

async function sha256BytesHex(value) {
  const digest = await crypto.subtle.digest("SHA-256", value);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function encode(value) {
  const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : value;
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function decode(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("Invalid base64url value");
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}
