import { HttpError, IDENTIFIER, expectKeys, json, readObject, stringField } from "./http";
import { DeviceGroup } from "./group";
import { Session } from "./session";

interface Env {
  SESSIONS: DurableObjectNamespace;
  GROUPS: DurableObjectNamespace;
  ASSETS: Fetcher;
}

export { DeviceGroup, Session };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const url = new URL(request.url);
      if (url.protocol === "http:" && url.hostname !== "localhost" && url.hostname !== "127.0.0.1") {
        url.protocol = "https:";
        return Response.redirect(url.toString(), 301);
      }
      if (!url.pathname.startsWith("/api/")) {
        return env.ASSETS.fetch(request);
      }
      if (request.method === "GET" && url.pathname === "/api/health") {
        return json({ ok: true });
      }
      if (request.method === "POST" && url.pathname === "/api/sessions") {
        const body = await readObject(request);
        expectKeys(body, ["sessionId", "managerTokenHash", "creatorPublicKey", "pairing"]);
        const sessionId = stringField(body, "sessionId", IDENTIFIER, 64);
        return sessionStub(env, sessionId).fetch(
          internalRequest("/create", request, JSON.stringify(body)),
        );
      }

      if (request.method === "POST" && url.pathname === "/api/groups") {
        const body = await readObject(request);
        const groupId = stringField(body, "groupId", IDENTIFIER, 64);
        return groupStub(env, groupId).fetch(
          internalRequest("/create", request, JSON.stringify(body)),
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

function sessionStub(env: Env, sessionId: string): DurableObjectStub {
  return env.SESSIONS.get(env.SESSIONS.idFromName(sessionId));
}

function groupStub(env: Env, groupId: string): DurableObjectStub {
  return env.GROUPS.get(env.GROUPS.idFromName(groupId));
}

function internalRequest(path: string, original: Request, body: string): Request {
  const headers = new Headers(original.headers);
  headers.delete("x-notify-guru-internal");
  return new Request(`https://session.internal${path}`, {
    method: original.method,
    headers,
    body,
  });
}

function publicRequest(url: URL, original: Request): Request {
  const headers = new Headers(original.headers);
  headers.delete("x-notify-guru-internal");
  return new Request(url, { method: original.method, headers, body: original.body });
}
