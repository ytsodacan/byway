import { parseRequest, signature, sigKey } from "./signature.js";
import { retime } from "./retime.js";
import { b64ToBytes } from "./wire.js";

async function getTemplate(env, key) {
  const raw = await env.TEMPLATES.get(key, "json");
  if (!raw) return null;
  return { res: b64ToBytes(raw.resBase64), headers: raw.headers || {}, t: raw.t };
}

/** The one captured register reply: same guest account every time (see README). */
export async function handleStatic(env) {
  const tpl = await getTemplate(env, "static");
  return tpl ? { body: tpl.res, headers: tpl.headers } : null;
}

/** The one captured login reply, retimed. Credentials are not checked in this v1 (see README). */
export async function handleLogin(env) {
  const tpl = await getTemplate(env, "login");
  if (!tpl) return null;
  const now = Date.now() / 1000;
  return { body: retime(tpl.res, now), headers: tpl.headers };
}

export async function handleGeo(env) {
  const tpl = await getTemplate(env, "geo");
  return tpl ? { body: tpl.res, headers: tpl.headers } : null;
}

export async function handleCommand(env, body) {
  const { lines, protos } = parseRequest(body);
  const sig = signature(lines, protos);
  const now = Date.now() / 1000;
  let tpl = await getTemplate(env, await sigKey(sig));
  let matched = true;
  if (!tpl) {
    tpl = await getTemplate(env, "fallback");
    matched = false;
  }
  if (!tpl) return null;
  return { body: retime(tpl.res, now), headers: tpl.headers, sig, matched };
}
