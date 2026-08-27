import { HttpError } from "./http";

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

export function randomIdentifier(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(18));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function decodeBase64URL(value: string): Uint8Array {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "="));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}
