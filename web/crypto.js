const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export async function createIdentity() {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  return {
    groupId: randomId(),
    keyPair,
    publicKey: encode(await crypto.subtle.exportKey("raw", keyPair.publicKey)),
  };
}

export async function deriveSessionKey(privateKey, creatorPublicKey, sessionId) {
  const publicKey = await crypto.subtle.importKey(
    "raw",
    decode(creatorPublicKey),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const sharedSecret = await crypto.subtle.deriveBits(
    { name: "ECDH", public: publicKey },
    privateKey,
    256,
  );
  const material = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: encoder.encode(sessionId),
      info: encoder.encode("notify.guru/session/v1"),
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function pairingProof(authSecret, sessionId, pairingId, groupId, groupPublicKey) {
  const key = await crypto.subtle.importKey(
    "raw",
    decode(authSecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const transcript = `v1\n${sessionId}\n${pairingId}\n${groupId}\n${groupPublicKey}`;
  return encode(await crypto.subtle.sign("HMAC", key, encoder.encode(transcript)));
}

export async function encryptResponse(key, sessionId, groupId, responseId, response) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce,
      additionalData: encoder.encode(responseAad(sessionId, groupId, responseId)),
    },
    key,
    encoder.encode(JSON.stringify(response)),
  );
  return { nonce: encode(nonce), ciphertext: encode(ciphertext) };
}

export async function decryptEvent(key, sessionId, envelope) {
  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: decode(envelope.nonce),
      additionalData: encoder.encode(eventAad(sessionId, envelope.groupId, envelope.eventId)),
    },
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

function eventAad(sessionId, groupId, eventId) {
  return `notify.guru/v1/event/${sessionId}/${groupId}/${eventId}`;
}

function responseAad(sessionId, groupId, responseId) {
  return `notify.guru/v1/response/${sessionId}/${groupId}/${responseId}`;
}

function encode(value) {
  const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : value;
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function decode(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("Invalid base64url value");
  }
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}
