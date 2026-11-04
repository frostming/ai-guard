import { publicOrigin, type Env } from "./config";
import { randomId, signToken, verifyToken } from "./crypto";
import { gh } from "./github";

const SESSION_COOKIE = "aig_session";
const STATE_COOKIE = "aig_oauth";
const SESSION_TTL = 60 * 60; // 1h
const STATE_TTL = 10 * 60;

export interface Session {
  login: string;
  id: number;
}

export function getCookie(request: Request, name: string): string | undefined {
  const header = request.headers.get("Cookie") ?? "";
  for (const part of header.split(/;\s*/)) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i) === name) return part.slice(i + 1);
  }
  return undefined;
}

function cookie(name: string, value: string, maxAge: number): string {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

export async function getSession(request: Request, env: Env): Promise<Session | null> {
  const s = await verifyToken<{ login: string; id: number; kind: string }>(env.SESSION_SECRET, getCookie(request, SESSION_COOKIE));
  return s && s.kind === "session" ? { login: s.login, id: s.id } : null;
}

/** Only allow redirects back to our own attestation pages. */
export function safeReturnTo(value: string | null): string {
  return value && /^\/attest\/[^/]+\/[^/]+\/\d+$/.test(value) ? value : "/";
}

export async function login(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const returnTo = safeReturnTo(url.searchParams.get("return_to"));
  const state = randomId();
  const stateToken = await signToken(env.SESSION_SECRET, { kind: "oauth", state, returnTo }, STATE_TTL);
  const authorize = new URL("https://github.com/login/oauth/authorize");
  authorize.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
  authorize.searchParams.set("redirect_uri", `${publicOrigin(env, request)}/auth/callback`);
  authorize.searchParams.set("state", state);
  authorize.searchParams.set("allow_signup", "false");
  return new Response(null, {
    status: 302,
    headers: { Location: authorize.toString(), "Set-Cookie": cookie(STATE_COOKIE, stateToken, STATE_TTL) },
  });
}

export async function callback(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const saved = await verifyToken<{ kind: string; state: string; returnTo: string }>(
    env.SESSION_SECRET,
    getCookie(request, STATE_COOKIE),
  );
  if (!code || !state || !saved || saved.kind !== "oauth" || saved.state !== state) {
    return new Response("Login expired or invalid state. Please start again.", { status: 400 });
  }

  const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json", "User-Agent": "ai-guard" },
    body: JSON.stringify({
      client_id: env.GITHUB_CLIENT_ID,
      client_secret: env.GITHUB_CLIENT_SECRET,
      code,
      redirect_uri: `${publicOrigin(env, request)}/auth/callback`,
    }),
  });
  const tokenJson = (await tokenRes.json()) as { access_token?: string; error_description?: string };
  if (!tokenJson.access_token) {
    return new Response(`GitHub login failed: ${tokenJson.error_description ?? "no token"}`, { status: 400 });
  }
  const user = await gh<{ login: string; id: number; type: string }>(tokenJson.access_token, "GET", "/user");
  if (user.type !== "User") return new Response("Only human user accounts can attest.", { status: 403 });

  // The user token is only used to learn who this is; we do not keep it.
  const session = await signToken(env.SESSION_SECRET, { kind: "session", login: user.login, id: user.id }, SESSION_TTL);
  const headers = new Headers({ Location: saved.returnTo });
  headers.append("Set-Cookie", cookie(SESSION_COOKIE, session, SESSION_TTL));
  headers.append("Set-Cookie", cookie(STATE_COOKIE, "", 0));
  return new Response(null, { status: 302, headers });
}

export function logout(): Response {
  return new Response(null, { status: 302, headers: { Location: "/", "Set-Cookie": cookie(SESSION_COOKIE, "", 0) } });
}

export interface TurnstileResult {
  success: boolean;
  action?: string;
  cdata?: string;
  hostname?: string;
  "error-codes"?: string[];
}

export async function verifyTurnstile(env: Env, token: string, ip: string | null): Promise<TurnstileResult> {
  const form = new FormData();
  form.append("secret", env.TURNSTILE_SECRET_KEY);
  form.append("response", token);
  if (ip) form.append("remoteip", ip);
  form.append("idempotency_key", crypto.randomUUID());
  const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: form });
  return (await res.json()) as TurnstileResult;
}
