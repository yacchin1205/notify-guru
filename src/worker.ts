import { HttpError, IDENTIFIER, expectKeys, json, readObject, stringField } from "./http";
import { Session } from "./session";

interface Env {
  SESSIONS: DurableObjectNamespace;
  ASSETS: Fetcher;
}

export { Session };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const url = new URL(request.url);
      if (url.protocol === "http:") {
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
        const forwarded = { ...body };
        delete forwarded.sessionId;
        return sessionStub(env, sessionId).fetch(
          internalRequest("/create", request, JSON.stringify(forwarded)),
        );
      }

      const match = /^\/api\/sessions\/([^/]+)(\/.*)?$/.exec(url.pathname);
      if (match === null) {
        throw new HttpError(404, "not_found", "Endpoint not found");
      }
      const sessionId = stringField({ sessionId: match[1] }, "sessionId", IDENTIFIER, 64);
      const internalUrl = new URL(`https://session.internal${match[2] ?? "/"}`);
      internalUrl.search = url.search;
      return sessionStub(env, sessionId).fetch(new Request(internalUrl, request));
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

function internalRequest(path: string, original: Request, body: string): Request {
  return new Request(`https://session.internal${path}`, {
    method: original.method,
    headers: original.headers,
    body,
  });
}
