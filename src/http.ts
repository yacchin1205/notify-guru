export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

export function json(data: unknown, status = 200): Response {
  return Response.json(data, {
    status,
    headers: {
      "cache-control": "no-store",
      "strict-transport-security": "max-age=15552000",
    },
  });
}

export async function readObject(request: Request): Promise<Record<string, unknown>> {
  if (request.headers.get("content-type")?.split(";", 1)[0] !== "application/json") {
    throw new HttpError(415, "invalid_content_type", "Content-Type must be application/json");
  }

  let value: unknown;
  try {
    value = await request.json();
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new HttpError(400, "invalid_json", "Request body is not valid JSON");
    }
    throw error;
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new HttpError(400, "invalid_json", "JSON body must be an object");
  }
  return value as Record<string, unknown>;
}

export function expectKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): void {
  for (const key of required) {
    if (!(key in value)) {
      throw new HttpError(400, "missing_field", `Missing field: ${key}`);
    }
  }

  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throw new HttpError(400, "unknown_field", `Unknown field: ${key}`);
    }
  }
}

export function stringField(
  value: Record<string, unknown>,
  key: string,
  pattern: RegExp,
  maxLength: number,
): string {
  const field = value[key];
  if (typeof field !== "string" || field.length === 0 || field.length > maxLength || !pattern.test(field)) {
    throw new HttpError(400, "invalid_field", `Invalid field: ${key}`);
  }
  return field;
}

export function integerQuery(url: URL, key: string): number {
  const raw = url.searchParams.get(key);
  if (raw === null) {
    return 0;
  }
  if (!/^(0|[1-9][0-9]*)$/.test(raw)) {
    throw new HttpError(400, "invalid_query", `Invalid query parameter: ${key}`);
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value)) {
    throw new HttpError(400, "invalid_query", `Invalid query parameter: ${key}`);
  }
  return value;
}

export function integerField(value: Record<string, unknown>, key: string): number {
  const field = value[key];
  if (!Number.isSafeInteger(field) || (field as number) < 0) {
    throw new HttpError(400, "invalid_field", `Invalid field: ${key}`);
  }
  return field as number;
}

export function bearerToken(request: Request): string {
  const header = request.headers.get("authorization");
  if (header === null || !header.startsWith("Bearer ")) {
    throw new HttpError(401, "missing_bearer", "Bearer token is required");
  }
  const token = header.slice(7);
  if (!BASE64URL.test(token) || token.length > 128) {
    throw new HttpError(401, "invalid_bearer", "Bearer token is invalid");
  }
  return token;
}

export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function equalHex(left: string, right: string): boolean {
  if (left.length !== right.length) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

export const IDENTIFIER = /^[A-Za-z0-9_-]{16,64}$/;
export const BASE64URL = /^[A-Za-z0-9_-]+$/;
export const SHA256_HEX = /^[a-f0-9]{64}$/;
