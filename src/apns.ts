export interface APNsConfig {
  keyId?: string;
  teamId?: string;
  privateKey?: string;
  topic: string;
}

export type APNsEnvironment = "sandbox" | "production";
export type APNsAlertKind = "notify" | "request";

export type APNsResult =
  | { outcome: "delivered" }
  | { outcome: "invalid-token"; reason: string }
  | { outcome: "permanent-failure"; reason: string }
  | { outcome: "retry"; reason: string; minimumDelayMs: number };

export class APNsTransportError extends Error {
  constructor(cause: unknown) {
    super("APNs transport failed", { cause });
    this.name = "APNsTransportError";
  }
}

const IDENTIFIER = /^[A-Z0-9]{10}$/;
const DEVICE_TOKEN = /^[a-f0-9]+$/;
const PROVIDER_TOKEN_REFRESH_SECONDS = 50 * 60;
const PROVIDER_TOKEN_UPDATE_DELAY_MS = 20 * 60 * 1000;
const SERVER_FAILURE_DELAY_MS = 15 * 60 * 1000;

interface ProviderTokenState {
  keyId: string;
  teamId: string;
  privateKey: string;
  issuedAt: number;
  value: string;
}

interface PendingProviderToken {
  keyId: string;
  teamId: string;
  privateKey: string;
  promise: Promise<string>;
}

let cachedProviderToken: ProviderTokenState | undefined;
let pendingProviderToken: PendingProviderToken | undefined;

export class APNsClient {
  constructor(
    private readonly config: APNsConfig,
    private readonly transport?: typeof fetch,
  ) {}

  async send(deviceToken: string, environment: APNsEnvironment, kind: APNsAlertKind): Promise<APNsResult> {
    if (!DEVICE_TOKEN.test(deviceToken)) {
      throw new Error("APNs device token must be lowercase hexadecimal");
    }
    const keyId = requiredIdentifier("APNS_KEY_ID", this.config.keyId);
    const teamId = requiredIdentifier("APNS_TEAM_ID", this.config.teamId);
    if (this.config.privateKey === undefined || this.config.privateKey.length === 0) {
      throw new Error("APNS_PRIVATE_KEY is not configured");
    }
    const host = environment === "sandbox" ? "api.sandbox.push.apple.com" : "api.push.apple.com";
    const authentication = await providerToken(keyId, teamId, this.config.privateKey);
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
      body: JSON.stringify({
        aps: {
          alert: kind === "notify" ? "A new notification is available." : "Your input is requested.",
          sound: "default",
        },
      }),
    };
    const transport = this.transport;
    let response: Response;
    try {
      response = transport === undefined ? await fetch(url, init) : await transport(url, init);
    } catch (error) {
      throw new APNsTransportError(error);
    }
    if (response.status === 200) {
      if ((await response.text()).length !== 0) {
        throw new Error("APNs success response contained an unexpected body");
      }
      return { outcome: "delivered" };
    }
    const error = await apnsError(response);
    if (
      error.reason === "BadDeviceToken" ||
      error.reason === "DeviceTokenNotForTopic" ||
      error.reason === "Unregistered"
    ) {
      return { outcome: "invalid-token", reason: error.reason };
    }
    if (error.reason === "ExpiredProviderToken") {
      invalidateProviderToken(authentication);
      return { outcome: "retry", reason: error.reason, minimumDelayMs: 0 };
    }
    if (response.status === 429) {
      const minimumDelayMs =
        error.reason === "TooManyProviderTokenUpdates"
          ? PROVIDER_TOKEN_UPDATE_DELAY_MS
          : Math.max(60_000, retryAfter(response));
      return { outcome: "retry", reason: error.reason, minimumDelayMs };
    }
    if (response.status === 500 || response.status === 503) {
      return {
        outcome: "retry",
        reason: error.reason,
        minimumDelayMs: Math.max(SERVER_FAILURE_DELAY_MS, retryAfter(response)),
      };
    }
    return { outcome: "permanent-failure", reason: error.reason };
  }
}

async function providerToken(keyId: string, teamId: string, privateKey: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const cached = cachedProviderToken;
  if (
    cached !== undefined &&
    cached.keyId === keyId &&
    cached.teamId === teamId &&
    cached.privateKey === privateKey &&
    cached.issuedAt <= now &&
    now - cached.issuedAt < PROVIDER_TOKEN_REFRESH_SECONDS
  ) {
    return cached.value;
  }
  const pending = pendingProviderToken;
  if (
    pending !== undefined &&
    pending.keyId === keyId &&
    pending.teamId === teamId &&
    pending.privateKey === privateKey
  ) {
    return pending.promise;
  }
  const promise = createProviderToken(keyId, teamId, privateKey, now).then((value) => {
    cachedProviderToken = { keyId, teamId, privateKey, issuedAt: now, value };
    return value;
  });
  pendingProviderToken = { keyId, teamId, privateKey, promise };
  try {
    return await promise;
  } finally {
    if (pendingProviderToken?.promise === promise) {
      pendingProviderToken = undefined;
    }
  }
}

async function createProviderToken(
  keyId: string,
  teamId: string,
  privateKey: string,
  issuedAt: number,
): Promise<string> {
  const header = encodeJSON({ alg: "ES256", kid: keyId });
  const payload = encodeJSON({ iss: teamId, iat: issuedAt });
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

function invalidateProviderToken(value: string): void {
  if (cachedProviderToken?.value === value) {
    cachedProviderToken = undefined;
  }
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
  if (typeof fields.reason !== "string" || !/^[A-Za-z][A-Za-z0-9]{0,63}$/.test(fields.reason)) {
    throw new Error(`APNs error response (${response.status}) has an invalid reason`);
  }
  if (fields.timestamp !== undefined) {
    if (typeof fields.timestamp !== "number" || !Number.isSafeInteger(fields.timestamp) || fields.timestamp < 0) {
      throw new Error(`APNs error response (${response.status}) has an invalid timestamp`);
    }
  }
  return { reason: fields.reason };
}

function retryAfter(response: Response): number {
  const value = response.headers.get("retry-after");
  if (value === null) {
    return 0;
  }
  if (/^[0-9]{1,6}$/.test(value)) {
    return Number(value) * 1000;
  }
  const time = Date.parse(value);
  if (!Number.isFinite(time)) {
    return 0;
  }
  return Math.max(0, time - Date.now());
}
