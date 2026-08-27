export interface APNsConfig {
  keyId?: string;
  teamId?: string;
  privateKey?: string;
  topic: string;
}

export type APNsEnvironment = "sandbox" | "production";

export type APNsResult = "delivered" | "invalid-token";

const IDENTIFIER = /^[A-Z0-9]{10}$/;
const DEVICE_TOKEN = /^[a-f0-9]+$/;

export class APNsClient {
  constructor(
    private readonly config: APNsConfig,
    private readonly transport?: typeof fetch,
  ) {}

  async send(deviceToken: string, environment: APNsEnvironment): Promise<APNsResult> {
    if (!DEVICE_TOKEN.test(deviceToken)) {
      throw new Error("APNs device token must be lowercase hexadecimal");
    }
    const keyId = requiredIdentifier("APNS_KEY_ID", this.config.keyId);
    const teamId = requiredIdentifier("APNS_TEAM_ID", this.config.teamId);
    if (this.config.privateKey === undefined || this.config.privateKey.length === 0) {
      throw new Error("APNS_PRIVATE_KEY is not configured");
    }
    const host = environment === "sandbox" ? "api.sandbox.push.apple.com" : "api.push.apple.com";
    const authentication = await token(keyId, teamId, this.config.privateKey);
    const url = `https://${host}/3/device/${deviceToken}`;
    const init: RequestInit = {
      method: "POST",
      headers: {
        authorization: `bearer ${authentication}`,
        "apns-push-type": "alert",
        "apns-priority": "10",
        "apns-topic": this.config.topic,
        "content-type": "application/json",
      },
      body: JSON.stringify({ aps: { alert: "A new notification is available." } }),
    };
    const transport = this.transport;
    const response = transport === undefined ? await fetch(url, init) : await transport(url, init);
    if (response.status === 200) {
      if ((await response.text()).length !== 0) {
        throw new Error("APNs success response contained an unexpected body");
      }
      return "delivered";
    }
    const error = await apnsError(response);
    if (
      error.reason === "BadDeviceToken" ||
      error.reason === "DeviceTokenNotForTopic" ||
      error.reason === "Unregistered"
    ) {
      return "invalid-token";
    }
    throw new Error(`APNs request failed (${response.status}): ${error.reason}`);
  }
}

async function token(keyId: string, teamId: string, privateKey: string): Promise<string> {
  const header = encodeJSON({ alg: "ES256", kid: keyId });
  const payload = encodeJSON({ iss: teamId, iat: Math.floor(Date.now() / 1000) });
  const message = `${header}.${payload}`;
  const key = await crypto.subtle.importKey(
    "pkcs8",
    decodePEM(privateKey),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    new TextEncoder().encode(message),
  );
  return `${message}.${base64url(new Uint8Array(signature))}`;
}

function requiredIdentifier(name: string, value: string | undefined): string {
  if (value === undefined || !IDENTIFIER.test(value)) {
    throw new Error(`${name} must be a 10-character uppercase identifier`);
  }
  return value;
}

function decodePEM(value: string): ArrayBuffer {
  const normalized = value.replaceAll("\r\n", "\n");
  const match = /^-----BEGIN PRIVATE KEY-----\n([A-Za-z0-9+/=\n]+)\n-----END PRIVATE KEY-----\n?$/.exec(normalized);
  if (match === null) {
    throw new Error("APNS_PRIVATE_KEY must be an unencrypted PKCS#8 PEM key");
  }
  const binary = atob(match[1].replaceAll("\n", ""));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0)).buffer;
}

function encodeJSON(value: unknown): string {
  return base64url(new TextEncoder().encode(JSON.stringify(value)));
}

function base64url(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

async function apnsError(response: Response): Promise<{ reason: string }> {
  const value: unknown = await response.json();
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`APNs error response (${response.status}) must be an object`);
  }
  const fields = value as Record<string, unknown>;
  const allowed = fields.timestamp === undefined ? ["reason"] : ["reason", "timestamp"];
  if (Object.keys(fields).sort().join(",") !== allowed.sort().join(",")) {
    throw new Error(`APNs error response (${response.status}) has unexpected fields`);
  }
  if (typeof fields.reason !== "string" || fields.reason.length === 0) {
    throw new Error(`APNs error response (${response.status}) has an invalid reason`);
  }
  if (fields.timestamp !== undefined) {
    if (typeof fields.timestamp !== "number" || !Number.isSafeInteger(fields.timestamp) || fields.timestamp < 0) {
      throw new Error(`APNs error response (${response.status}) has an invalid timestamp`);
    }
  }
  return { reason: fields.reason };
}
