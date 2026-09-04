import { HttpError } from "./http";

export const GENESIS_TRANSITION_HASH = "0".repeat(64);

export interface TransitionMember {
  deviceId: string;
  signingPublicKey: string;
  encryptionPublicKey: string;
}

export interface TransitionPackageDigest {
  deviceId: string;
  sha256: string;
}

export interface GroupTransitionContent {
  transitionId: string;
  previousHash: string;
  timestamp: number;
  actorDeviceId: string;
  publicKey: string;
  recreated: boolean;
  members: TransitionMember[];
  packageDigests: TransitionPackageDigest[];
}

export interface SignedGroupTransition extends GroupTransitionContent {
  actorSignature: string;
  continuitySignature: string;
  transitionHash: string;
}

export interface SignedSessionDescriptor {
  sessionId: string;
  groupId: string;
  protocolVersion: number;
  creatorPublicKey: string;
  keyTimestamp: number;
  transitionHash: string;
  actorDeviceId: string;
  actorSignature: string;
  continuitySignature: string;
}

export function sessionDescriptorTranscript(descriptor: Omit<SignedSessionDescriptor, "actorSignature" | "continuitySignature">): string {
  return [
    "notify.guru/session-descriptor/v1",
    descriptor.sessionId,
    descriptor.groupId,
    String(descriptor.protocolVersion),
    descriptor.creatorPublicKey,
    String(descriptor.keyTimestamp),
    descriptor.transitionHash,
    descriptor.actorDeviceId,
  ].join("\n");
}

export async function verifyP256Signature(
  publicKey: string,
  signature: string,
  transcript: string,
): Promise<boolean> {
  let key: CryptoKey;
  let signatureBytes: Uint8Array;
  try {
    key = await crypto.subtle.importKey(
      "raw",
      decodeBase64URL(publicKey),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    signatureBytes = decodeBase64URL(signature);
  } catch {
    throw new HttpError(400, "invalid_signature_material", "P-256 public key or signature is invalid");
  }
  if (signatureBytes.length !== 64) {
    throw new HttpError(400, "invalid_signature_material", "P-256 signature must contain 64 bytes");
  }
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    signatureBytes,
    new TextEncoder().encode(transcript),
  );
}

export async function validateP256KeyAgreementPublicKey(publicKey: string): Promise<boolean> {
  try {
    await crypto.subtle.importKey(
      "raw",
      decodeBase64URL(publicKey),
      { name: "ECDH", namedCurve: "P-256" },
      false,
      [],
    );
    return true;
  } catch {
    return false;
  }
}

export function randomIdentifier(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(18));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export function groupTransitionTranscript(groupId: string, transition: GroupTransitionContent): string {
  const members = [...transition.members].sort((left, right) => compareCanonical(left.deviceId, right.deviceId));
  const packages = [...transition.packageDigests].sort((left, right) => compareCanonical(left.deviceId, right.deviceId));
  const lines = [
    "notify.guru/group-transition/v1",
    groupId,
    transition.transitionId,
    transition.previousHash,
    String(transition.timestamp),
    transition.actorDeviceId,
    transition.publicKey,
    transition.recreated ? "1" : "0",
    String(members.length),
  ];
  for (const member of members) {
    lines.push(member.deviceId, member.signingPublicKey, member.encryptionPublicKey);
  }
  lines.push(String(packages.length));
  for (const item of packages) lines.push(item.deviceId, item.sha256);
  return lines.join("\n");
}

function compareCanonical(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export async function groupTransitionHash(
  groupId: string,
  transition: GroupTransitionContent,
  _actorSignature?: string,
  _continuitySignature?: string,
): Promise<string> {
  return sha256Text([
    "notify.guru/group-transition-hash/v2",
    groupTransitionTranscript(groupId, transition),
  ].join("\n"));
}

export async function groupKeyPackageDigest(keyPackage: {
  deviceId: string;
  ephemeralPublicKey: string;
  nonce: string;
  ciphertext: string;
}): Promise<string> {
  return sha256Text([
    "notify.guru/group-key-package/v1",
    keyPackage.deviceId,
    keyPackage.ephemeralPublicKey,
    keyPackage.nonce,
    keyPackage.ciphertext,
  ].join("\n"));
}

export async function deviceRequestBindingHash(request: {
  requestId: string;
  deviceId: string;
  signingPublicKey: string;
  accessHash: string;
  encryptionPublicKey: string;
  protocolVersion: number;
}): Promise<string> {
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

async function sha256Text(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function decodeBase64URL(value: string): Uint8Array {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "="));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}
