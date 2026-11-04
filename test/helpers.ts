import { generateKeyPairSync, createHmac } from "node:crypto";
import { vi } from "vitest";
import type { Env } from "../src/config";
import { signToken } from "../src/crypto";

export const { privateKey: PKCS1_PEM, publicKey: PUBLIC_PEM } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs1", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" },
});

export const ORIGIN = "https://guard.test";
export const SHA = "a".repeat(40);

export function makeEnv(overrides: Partial<Env> = {}): Env {
  return {
    GITHUB_APP_ID: "42",
    GITHUB_CLIENT_ID: "Iv1.client",
    TURNSTILE_SITE_KEY: "0xSITEKEY",
    GITHUB_APP_PRIVATE_KEY: PKCS1_PEM,
    GITHUB_WEBHOOK_SECRET: "whsec",
    GITHUB_CLIENT_SECRET: "csec",
    TURNSTILE_SECRET_KEY: "0xREALSECRET",
    SESSION_SECRET: "session-secret",
    PUBLIC_URL: ORIGIN,
    ...overrides,
  };
}

export function sign(body: string, secret = "whsec"): string {
  return `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;
}

export async function sessionCookie(env: Env, login: string): Promise<string> {
  return `aig_session=${await signToken(env.SESSION_SECRET, { kind: "session", login, id: 1 }, 3600)}`;
}

export function makeCtx() {
  const pending: Promise<unknown>[] = [];
  return {
    ctx: { waitUntil: (p: Promise<unknown>) => pending.push(p), passThroughOnException() {} } as unknown as ExecutionContext,
    settle: () => Promise.all(pending),
  };
}

export interface Call {
  method: string;
  url: string;
  body: any;
}

export interface FakeState {
  prAuthor: string;
  prState: string;
  headSha: string;
  permissions: Record<string, string>;
  checkRuns: { id: number; conclusion: string | null; app: { id: number } }[];
  turnstile: Record<string, unknown>;
  comments: { id: number; body: string; performed_via_github_app: { id: number } | null }[];
}

/** Install a fake `fetch` that emulates the bits of GitHub + Turnstile the worker uses. */
export function fakeGitHub(state: Partial<FakeState> = {}) {
  const s: FakeState = {
    prAuthor: "alice",
    prState: "open",
    headSha: SHA,
    permissions: {},
    checkRuns: [{ id: 7, conclusion: "action_required", app: { id: 42 } }],
    turnstile: { success: true, action: "attest", cdata: SHA, hostname: "guard.test" },
    comments: [],
    ...state,
  };
  const calls: Call[] = [];
  const json = (data: unknown, status = 200) =>
    new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });

  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    let body: any = init?.body;
    if (typeof body === "string") body = JSON.parse(body);
    else if (body instanceof FormData) body = Object.fromEntries(body.entries());
    calls.push({ method, url, body });
    const path = url.replace("https://api.github.com", "");

    if (url.startsWith("https://challenges.cloudflare.com/")) return json(s.turnstile);
    if (path.startsWith("/app/installations/") && method === "POST")
      return json({ token: "ghs_inst", expires_at: new Date(Date.now() + 3600_000).toISOString() }, 201);
    if (path === "/repos/acme/web/installation") return json({ id: 99 });
    if (path === "/repos/acme/web/pulls/5")
      return json({
        number: 5,
        title: "Add <script> feature",
        state: s.prState,
        html_url: "https://github.com/acme/web/pull/5",
        user: { login: s.prAuthor, type: "User" },
        head: { sha: s.headSha },
        additions: 10,
        deletions: 2,
        changed_files: 3,
      });
    const perm = /^\/repos\/acme\/web\/collaborators\/([^/]+)\/permission$/.exec(path);
    if (perm) {
      const p = s.permissions[decodeURIComponent(perm[1]!)];
      return p ? json({ permission: p }) : json({ message: "Not Found" }, 404);
    }
    if (path.startsWith(`/repos/acme/web/commits/`) && path.includes("/check-runs")) return json({ check_runs: s.checkRuns });
    if (path === "/repos/acme/web/check-runs" && method === "POST") return json({ id: 8 }, 201);
    if (path.startsWith("/repos/acme/web/check-runs/") && method === "PATCH") return json({ id: 7 });
    if (path.startsWith("/repos/acme/web/issues/5/comments?") && method === "GET") {
      const page = Number(new URL(url).searchParams.get("page") ?? "1");
      return json(s.comments.slice((page - 1) * 100, page * 100));
    }
    if (path === "/repos/acme/web/issues/5/comments" && method === "POST") {
      const c = { id: 100 + s.comments.length, body: body.body, performed_via_github_app: { id: 42 } };
      s.comments.push(c);
      return json(c, 201);
    }
    const editComment = /^\/repos\/acme\/web\/issues\/comments\/(\d+)$/.exec(path);
    if (editComment && method === "PATCH") {
      const c = s.comments.find((x) => x.id === Number(editComment[1]));
      if (!c) return json({ message: "Not Found" }, 404);
      c.body = body.body;
      return json(c);
    }
    return json({ message: `unexpected ${method} ${path}` }, 500);
  });
  vi.stubGlobal("fetch", fetchMock);
  return { calls, state: s };
}

/** A comment as this App would have left it after an attestation. */
export function attestedComment(login = "bob", sha = "0".repeat(40), appId: number | null = 42) {
  const record = JSON.stringify({ login, sha, statement: "I have read it", at: "2026-11-04T00:00:00.000Z" });
  return {
    id: 55,
    body: `<!-- ai-guard -->\n<!-- ai-guard:attestation ${record} -->\nattested`,
    performed_via_github_app: appId === null ? null : { id: appId },
  };
}
