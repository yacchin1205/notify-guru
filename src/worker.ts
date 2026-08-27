import { HttpError, IDENTIFIER, expectKeys, json, readObject, stringField } from "./http";
import { DeviceRegistry } from "./device";
import { DeviceGroup } from "./group";
import { Session } from "./session";

interface Env {
  SESSIONS: DurableObjectNamespace<Session>;
  GROUPS: DurableObjectNamespace<DeviceGroup>;
  DEVICES: DurableObjectNamespace<DeviceRegistry>;
  ASSETS: Fetcher;
}

export { DeviceGroup, DeviceRegistry, Session };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const url = new URL(request.url);
      const requestHost = request.headers.get("host")?.split(":", 1)[0];
      const miniflareLoopback = url.hostname === "notify.guru"
        && request.headers.get("mf-original-hostname") === "notify.guru"
        && request.headers.get("cf-connecting-ip") === "127.0.0.1";
      const localRequest = miniflareLoopback
        || [url.hostname, requestHost].some((host) => host === "localhost" || host === "127.0.0.1");
      if (url.protocol === "http:" && !localRequest) {
        url.protocol = "https:";
        return Response.redirect(url.toString(), 301);
      }
      if (!url.pathname.startsWith("/api/")) {
        return env.ASSETS.fetch(request);
      }
      if (request.method === "GET" && url.pathname === "/api/health") {
        return json({ ok: true });
      }
      if (request.method === "POST" && url.pathname === "/api/devices") {
        return deviceRegistry(env).fetch(publicRequest(new URL("https://devices.internal/devices"), request));
      }
      const devicePushMatch = /^\/api\/devices\/([^/]+)\/push$/.exec(url.pathname);
      if (request.method === "PUT" && devicePushMatch !== null) {
        const deviceId = stringField({ deviceId: devicePushMatch[1] }, "deviceId", IDENTIFIER, 64);
        return deviceRegistry(env).fetch(publicRequest(
          new URL(`https://devices.internal/devices/${deviceId}/push`),
          request,
        ));
      }
      if (request.method === "POST" && url.pathname === "/api/device-requests") {
        return deviceRegistry(env).fetch(publicRequest(
          new URL("https://devices.internal/device-requests"),
          request,
        ));
      }
      const deviceRequestMatch = /^\/api\/device-requests\/([^/]+)$/.exec(url.pathname);
      if (request.method === "GET" && deviceRequestMatch !== null) {
        const requestId = stringField({ requestId: deviceRequestMatch[1] }, "requestId", IDENTIFIER, 64);
        const internalUrl = new URL(`https://devices.internal/device-requests/${requestId}`);
        internalUrl.search = url.search;
        return deviceRegistry(env).fetch(publicRequest(internalUrl, request));
      }
      if (request.method === "POST" && url.pathname === "/api/sessions") {
        const body = await readObject(request);
        expectKeys(body, ["sessionId", "managerTokenHash", "creatorPublicKey", "pairing"]);
        const sessionId = stringField(body, "sessionId", IDENTIFIER, 64);
        return sessionStub(env, sessionId).fetch(
          forwardedRequest("/create", request, JSON.stringify(body)),
        );
      }

      if (request.method === "POST" && url.pathname === "/api/groups") {
        const body = await readObject(request);
        const groupId = stringField(body, "groupId", IDENTIFIER, 64);
        return groupStub(env, groupId).fetch(
          forwardedRequest("/create", request, JSON.stringify(body)),
        );
      }

      const groupMatch = /^\/api\/groups\/([^/]+)(\/.*)?$/.exec(url.pathname);
      if (groupMatch !== null) {
        const groupId = stringField({ groupId: groupMatch[1] }, "groupId", IDENTIFIER, 64);
        const internalUrl = new URL(`https://group.internal${groupMatch[2] ?? "/"}`);
        internalUrl.search = url.search;
        return groupStub(env, groupId).fetch(publicRequest(internalUrl, request));
      }

      const match = /^\/api\/sessions\/([^/]+)(\/.*)?$/.exec(url.pathname);
      if (match === null) {
        throw new HttpError(404, "not_found", "Endpoint not found");
      }
      const sessionId = stringField({ sessionId: match[1] }, "sessionId", IDENTIFIER, 64);
      const internalUrl = new URL(`https://session.internal${match[2] ?? "/"}`);
      internalUrl.search = url.search;
      return sessionStub(env, sessionId).fetch(publicRequest(internalUrl, request));
    } catch (error) {
      if (error instanceof HttpError) {
        return json({ error: error.code, message: error.message }, error.status);
      }
      throw error;
    }
  },
};

function sessionStub(env: Env, sessionId: string): DurableObjectStub<Session> {
  return env.SESSIONS.get(env.SESSIONS.idFromName(sessionId));
}

function groupStub(env: Env, groupId: string): DurableObjectStub<DeviceGroup> {
  return env.GROUPS.get(env.GROUPS.idFromName(groupId));
}

function deviceRegistry(env: Env): DurableObjectStub<DeviceRegistry> {
  return env.DEVICES.get(env.DEVICES.idFromName("registry"));
}

function forwardedRequest(path: string, original: Request, body: string): Request {
  const headers = new Headers(original.headers);
  return new Request(`https://session.internal${path}`, {
    method: original.method,
    headers,
    body,
  });
}

function publicRequest(url: URL, original: Request): Request {
  const headers = new Headers(original.headers);
  return new Request(url, { method: original.method, headers, body: original.body });
}
