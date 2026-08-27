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
    protocolVersion: 2,
    deviceId: randomId(),
    accessToken: randomToken(),
    encryptionKeyPair,
    encryptionPublicKey: encode(await crypto.subtle.exportKey("raw", encryptionKeyPair.publicKey)),
    signingKeyPair,
    signingPublicKey: encode(await crypto.subtle.exportKey("raw", signingKeyPair.publicKey)),
    group: null,
    invitations: {},
  };
}

export async function createGeneration(generation) {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"],
  );
  const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  if (typeof jwk.d !== "string") {
    throw new Error("Generated P-256 key did not contain private material");
  }
  return {
    generation,
    publicKey: encode(await crypto.subtle.exportKey("raw", pair.publicKey)),
    privateKey: jwk.d,
  };
}

export async function createKeyPackage(groupId, generation, device) {
  const ephemeral = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"],
  );
  const recipient = await importPublic(device.encryptionPublicKey, "ECDH");
  const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: recipient }, ephemeral.privateKey, 256);
  const context = packageContext(groupId, generation.generation, device.deviceId);
  const key = await hkdfKey(shared, context);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: encoder.encode(context) },
    key,
    encoder.encode([
      "notify.guru/group-generation-key/v1",
      String(generation.generation),
      generation.publicKey,
      generation.privateKey,
    ].join("\n")),
  );
  return {
    generation: generation.generation,
    deviceId: device.deviceId,
    ephemeralPublicKey: encode(await crypto.subtle.exportKey("raw", ephemeral.publicKey)),
    nonce: encode(nonce),
    ciphertext: encode(ciphertext),
  };
}

export async function openKeyPackage(identity, groupId, expectedPublicKey, keyPackage) {
  if (keyPackage.deviceId !== identity.deviceId) {
    throw new Error("Key package targets another device");
  }
  const ephemeral = await importPublic(keyPackage.ephemeralPublicKey, "ECDH");
  const shared = await crypto.subtle.deriveBits(
    { name: "ECDH", public: ephemeral }, identity.encryptionKeyPair.privateKey, 256,
  );
  const context = packageContext(groupId, keyPackage.generation, identity.deviceId);
  const key = await hkdfKey(shared, context);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: decode(keyPackage.nonce), additionalData: encoder.encode(context) },
    key,
    decode(keyPackage.ciphertext),
  );
  const fields = decoder.decode(plaintext).split("\n");
  const generation = fields.length === 4 ? {
    generation: Number(fields[1]),
    publicKey: fields[2],
    privateKey: fields[3],
  } : null;
  if (
    generation === null || fields[0] !== "notify.guru/group-generation-key/v1"
    || generation.generation !== keyPackage.generation
    || typeof generation.publicKey !== "string" || typeof generation.privateKey !== "string"
    || (expectedPublicKey !== undefined && generation.publicKey !== expectedPublicKey)
  ) {
    throw new Error("Key package contains an invalid generation key");
  }
  await generationPrivateKey(generation, "ECDH", ["deriveBits"]);
  return generation;
}

export async function deriveSessionKey(generation, creatorPublicKey, sessionId, groupId) {
  const privateKey = await generationPrivateKey(generation, "ECDH", ["deriveBits"]);
  const publicKey = await importPublic(creatorPublicKey, "ECDH");
  const sharedSecret = await crypto.subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256);
  return hkdfKey(sharedSecret, `notify.guru/session/v2\n${sessionId}\n${groupId}\n${generation.generation}`);
}

export async function pairingProof(authSecret, sessionId, pairingId, groupId, revision, generation, groupPublicKey) {
  const key = await crypto.subtle.importKey(
    "raw", decode(authSecret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const transcript = `v2\n${sessionId}\n${pairingId}\n${groupId}\n${revision}\n${generation}\n${groupPublicKey}`;
  return encode(await crypto.subtle.sign("HMAC", key, encoder.encode(transcript)));
}

export function groupCreateTranscript(groupId, identity, generation, packagesHash) {
  return [
    "notify.guru/group-create/v1", groupId, identity.deviceId, identity.encryptionPublicKey,
    identity.signingPublicKey, generation.publicKey, packagesHash,
  ].join("\n");
}

export function transitionTranscript(groupId, transition) {
  return [
    "notify.guru/group-transition/v1", groupId, String(transition.revision),
    String(transition.previousGeneration), String(transition.generation), transition.generationPublicKey,
    transition.action, transition.actorDeviceId, transition.targetDeviceId, transition.packagesHash,
  ].join("\n");
}

export async function signDevice(identity, transcript) {
  return sign(identity.signingKeyPair.privateKey, transcript);
}

export async function signGeneration(generation, transcript) {
  return sign(await generationPrivateKey(generation, "ECDSA", ["sign"]), transcript);
}

export async function verifySignature(publicKey, signature, transcript) {
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" }, await importPublic(publicKey, "ECDSA"),
    decode(signature), encoder.encode(transcript),
  );
}

export async function hashPackages(packages) {
  const canonical = [...packages]
    .sort((left, right) => left.generation - right.generation || left.deviceId.localeCompare(right.deviceId))
    .map((item) => [String(item.generation), item.deviceId, item.ephemeralPublicKey, item.nonce, item.ciphertext].join("\n"))
    .join("\n--\n");
  return hashToken(canonical);
}

export async function verificationCode(invitation, pending) {
  const transcript = [
    "notify.guru/device-verification/v1", invitation.groupId, invitation.invitationId,
    invitation.invitationToken, pending.deviceId, pending.encryptionPublicKey, pending.signingPublicKey,
  ].join("\n");
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(transcript)));
  const number = ((digest[0] << 16) | (digest[1] << 8) | digest[2]) % 1_000_000;
  return String(number).padStart(6, "0");
}

export async function encryptResponse(key, sessionId, groupId, generation, responseId, response) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: encoder.encode(responseAad(sessionId, groupId, generation, responseId)) },
    key,
    encoder.encode(JSON.stringify(response)),
  );
  return { nonce: encode(nonce), ciphertext: encode(ciphertext) };
}

export async function decryptEvent(key, sessionId, envelope) {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: decode(envelope.nonce), additionalData: encoder.encode(eventAad(sessionId, envelope.groupId, envelope.generation, envelope.eventId)) },
    key,
    decode(envelope.ciphertext),
  );
  return JSON.parse(decoder.decode(plaintext));
}

export async function encryptLegacyResponse(key, sessionId, groupId, responseId, response) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: encoder.encode(`notify.guru/v1/response/${sessionId}/${groupId}/${responseId}`) },
    key,
    encoder.encode(JSON.stringify(response)),
  );
  return { nonce: encode(nonce), ciphertext: encode(ciphertext) };
}

export async function decryptLegacyEvent(key, sessionId, envelope) {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: decode(envelope.nonce), additionalData: encoder.encode(`notify.guru/v1/event/${sessionId}/${envelope.groupId}/${envelope.eventId}`) },
    key,
    decode(envelope.ciphertext),
  );
  return JSON.parse(decoder.decode(plaintext));
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

async function generationPrivateKey(generation, algorithm, usages) {
  const raw = decode(generation.publicKey);
  if (raw.length !== 65 || raw[0] !== 4) {
    throw new Error("Invalid generation public key");
  }
  const jwk = {
    kty: "EC", crv: "P-256", x: encode(raw.slice(1, 33)), y: encode(raw.slice(33, 65)),
    d: generation.privateKey, ext: false,
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
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function sign(privateKey, transcript) {
  return encode(await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, privateKey, encoder.encode(transcript),
  ));
}

function packageContext(groupId, generation, deviceId) {
  return `notify.guru/group-package/v1\n${groupId}\n${generation}\n${deviceId}`;
}

function eventAad(sessionId, groupId, generation, eventId) {
  return `notify.guru/v2/event/${sessionId}/${groupId}/${generation}/${eventId}`;
}

function responseAad(sessionId, groupId, generation, responseId) {
  return `notify.guru/v2/response/${sessionId}/${groupId}/${generation}/${responseId}`;
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
