import { injectCustomGallery, customThemeCampaign } from "./marketplace.js";
import { handleStatic, handleLogin, handleCommand, handleGeo } from "./templates.js";

const DROP = new Set(["content-length", "content-encoding", "transfer-encoding", "connection", "x-pserver-passthrough"]);

function responseHeaders(h) {
  const out = { "Content-Type": "application/octet-stream" };
  for (const [k, v] of Object.entries(h || {})) {
    if (!DROP.has(k.toLowerCase())) out[k] = v;
  }
  return out;
}

function passthrough() {
  // tells the local relay: don't answer this, let it reach real Waze
  return new Response(null, { status: 204, headers: { "X-Pserver-Passthrough": "1" } });
}

export default {
  async fetch(request, env) {
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
      if (!custom) return new Response("not found", { status: 404 }); // relay falls through to real Waze
      return new Response(JSON.stringify(custom), { status: 200, headers: { "Content-Type": "application/json" } });
    }

    if (url.pathname === "/gallery/patch" && request.method === "POST") {
      const raw = new Uint8Array(await request.arrayBuffer());
      const patched = injectCustomGallery(raw);
      return new Response(patched ?? raw, { status: 200, headers: { "Content-Type": "application/json" } });
    }

    if (url.pathname.startsWith("/rtserver/")) {
      const kind = url.pathname.split("/")[2]; // login | static | command
      const body = new Uint8Array(await request.arrayBuffer());
      let result = null;

      if (kind === "static") {
        result = await handleStatic(env);
      } else if (kind === "login") {
        // same heuristic as pserver.py's is_geo(): no schema needed, just a substring check
        const head = new TextDecoder("utf-8", { fatal: false }).decode(body.slice(0, Math.min(body.length, 8192)));
        if (head.includes("GetGeoServerConfig")) {
          result = await handleGeo(env);
          if (!result) return passthrough();
        } else {
          result = await handleLogin(env);
        }
      } else if (kind === "command") {
        result = await handleCommand(env, body);
      }

      if (!result) return passthrough();
      return new Response(result.body, { status: 200, headers: responseHeaders(result.headers) });
    }

    return new Response("pserver worker: unrecognized route", { status: 404 });
  },
};
