import { injectCustomGallery, customThemeCampaign } from "./marketplace.js";
import { handleStatic, handleLogin, handleCommand, handleGeo } from "./templates.js";

const DROP = new Set(["content-length", "content-encoding", "transfer-encoding", "connection", "x-pserver-passthrough"]);

function buildHeaders(h) {
  const out = new Headers({ "content-type": "application/octet-stream" });
  for (const [k, v] of Object.entries(h || {})) {
    if (DROP.has(k.toLowerCase())) continue;
    try { out.set(k, v); } catch (_) { /* invalid header from capture: skip */ }
  }
  return out;
}

function passthrough() {
  return new Response(null, { status: 204, headers: { "X-Pserver-Passthrough": "1" } });
}

function authorized(request, env) {
  const want = env.RELAY_KEY;
  const got = request.headers.get("x-relay-key") || "";
  if (!want || got.length !== want.length) return false;
  let diff = 0;
  for (let i = 0; i < want.length; i++) diff |= want.charCodeAt(i) ^ got.charCodeAt(i);
  return diff === 0;
}

export default {
  async fetch(request, env) {
    // This Worker serves captured session/login data: it must never be publicly readable.
    if (!env.RELAY_KEY) return new Response("RELAY_KEY secret not configured", { status: 503 });
    if (!authorized(request, env)) return new Response("forbidden", { status: 403 });

    const url = new URL(request.url);

    if (url.pathname.startsWith("/private/")) {
      const name = decodeURIComponent(url.pathname.slice("/private/".length));
      const file = await env.CONFIG.get("file:" + name, "arrayBuffer");
      if (!file) return new Response("not found", { status: 404 });
      const ctype = (await env.CONFIG.get("file-type:" + name)) || "application/octet-stream";
      return new Response(file, { status: 200, headers: { "Content-Type": ctype, "Cache-Control": "no-cache" } });
    }

    if (url.pathname.startsWith("/gallery/theme-campaign/")) {
      const cid = decodeURIComponent(url.pathname.split("/").pop());
      const custom = customThemeCampaign(cid);
      if (!custom) return new Response("not found", { status: 404 });
      return new Response(JSON.stringify(custom), { status: 200, headers: { "Content-Type": "application/json" } });
    }

    if (url.pathname === "/gallery/patch" && request.method === "POST") {
      const raw = new Uint8Array(await request.arrayBuffer());
      const patched = injectCustomGallery(raw);
      return new Response(patched ?? raw, { status: 200, headers: { "Content-Type": "application/json" } });
    }

    if (url.pathname.startsWith("/rtserver/")) {
      const kind = url.pathname.split("/")[2];
      const body = new Uint8Array(await request.arrayBuffer());
      let result = null;

      if (kind === "static") {
        result = await handleStatic(env);
      } else if (kind === "login") {
        const head = new TextDecoder("utf-8", { fatal: false }).decode(body.slice(0, Math.min(body.length, 8192)));
        if (head.includes("GetGeoServerConfig")) {
          result = await handleGeo(env);
        } else {
          result = await handleLogin(env);
        }
      } else if (kind === "command") {
        result = await handleCommand(env, body);
      }

      if (!result) return passthrough();
      const headers = buildHeaders(result.headers);
      if (result.sig !== undefined) {
        headers.set("x-pserver-sig", encodeURIComponent(result.sig).slice(0, 400));
        headers.set("x-pserver-matched", result.matched ? "1" : "0");
      }
      return new Response(result.body, { status: 200, headers });
    }

    return new Response("pserver worker: unrecognized route", { status: 404 });
  },
};
