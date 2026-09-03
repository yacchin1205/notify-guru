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

export async function pairingProof(authSecret, protocolVersion, sessionId, pairingId, groupId, timestamp, groupPublicKey) {
  const key = await crypto.subtle.importKey(
    "raw", decode(authSecret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const transcript = `v${protocolVersion}\n${sessionId}\n${pairingId}\n${groupId}\n${timestamp}\n${groupPublicKey}`;
  return encode(await crypto.subtle.sign("HMAC", key, encoder.encode(transcript)));
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
