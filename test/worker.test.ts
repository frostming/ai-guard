import { createPublicKey, createVerify } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import worker from "../src/index";
import { canAttest } from "../src/attest";
import { attestedCommentBody, findAppComment } from "../src/record";
import { b64urlDecode, createAppJwt, importRsaPrivateKey, signToken, verifyToken, verifyWebhookSignature } from "../src/crypto";
import { attestedComment, type Call, fakeGitHub, makeCtx, makeEnv, ORIGIN, PKCS1_PEM, PUBLIC_PEM, SHA, sessionCookie, sign } from "./helpers";

afterEach(() => vi.unstubAllGlobals());

describe("crypto", () => {
  it("verifies GitHub webhook signatures and rejects tampering", async () => {
    expect(await verifyWebhookSignature("whsec", "{}", sign("{}"))).toBe(true);
    expect(await verifyWebhookSignature("whsec", "{ }", sign("{}"))).toBe(false);
    expect(await verifyWebhookSignature("whsec", "{}", sign("{}", "other"))).toBe(false);
    expect(await verifyWebhookSignature("whsec", "{}", null)).toBe(false);
    expect(await verifyWebhookSignature("whsec", "{}", "sha256=zz")).toBe(false);
  });

  it("signed tokens reject tampering and expiry", async () => {
    const t = await signToken("k", { login: "alice" }, 60);
    expect((await verifyToken<{ login: string }>("k", t))?.login).toBe("alice");
    expect(await verifyToken("other", t)).toBeNull();
    const [body, sig] = t.split(".");
    const forged = btoa(JSON.stringify({ login: "mallory", exp: 9e9 })).replace(/=+$/, "");
    expect(await verifyToken("k", `${forged}.${sig}`)).toBeNull();
    expect(await verifyToken("k", `${body}.`)).toBeNull();
    expect(await verifyToken("k", await signToken("k", { a: 1 }, -1))).toBeNull();
  });

  it("imports GitHub's PKCS#1 key (also with escaped newlines) and signs a valid RS256 app JWT", async () => {
    for (const pem of [PKCS1_PEM, PKCS1_PEM.replace(/\n/g, "\\n")]) {
      const jwt = await createAppJwt("42", await importRsaPrivateKey(pem), 1_000_000);
      const [h, p, s] = jwt.split(".");
      const verifier = createVerify("RSA-SHA256");
      verifier.update(`${h}.${p}`);
      expect(verifier.verify(createPublicKey(PUBLIC_PEM), Buffer.from(b64urlDecode(s!)))).toBe(true);
      expect(JSON.parse(new TextDecoder().decode(b64urlDecode(p!)))).toEqual({ iat: 999_940, exp: 1_000_540, iss: "42" });
    }
  });
});

describe("canAttest policy", () => {
  it.each([
    ["author_or_writers", "alice", "alice", "none", true],
    ["author_or_writers", "bob", "alice", "write", true],
    ["author_or_writers", "bob", "alice", "triage", false],
    ["author", "Alice", "alice", "none", true],
    ["author", "bob", "alice", "admin", false],
    ["writers", "alice", "alice", "read", false],
    ["writers", "carol", "dependabot[bot]", "maintain", true],
  ] as const)("%s: %s on PR by %s with %s -> %s", (policy, login, author, perm, expected) => {
    expect(canAttest(policy, login, author, perm)).toBe(expected);
  });
});

async function webhook(env = makeEnv(), event: string, payload: unknown, signature?: string) {
  const body = JSON.stringify(payload);
  const { ctx, settle } = makeCtx();
  const res = await worker.fetch(
    new Request(`${ORIGIN}/webhook`, {
      method: "POST",
      body,
      headers: { "X-GitHub-Event": event, "X-Hub-Signature-256": signature ?? sign(body) },
    }),
    env,
    ctx,
  );
  await settle();
  return res;
}

const prPayload = (action: string) => ({
  action,
  installation: { id: 99 },
  repository: { name: "web", owner: { login: "acme" } },
  pull_request: { number: 5, head: { sha: SHA }, user: { login: "alice", type: "User" } },
});

describe("webhook", () => {
  it("rejects unsigned deliveries without calling GitHub", async () => {
    const { calls } = fakeGitHub();
    const res = await webhook(makeEnv(), "pull_request", prPayload("opened"), "sha256=00");
    expect(res.status).toBe(401);
    expect(calls).toHaveLength(0);
  });

  it("on PR opened: creates a blocking check run linking to the attestation page and comments", async () => {
    const { calls, state } = fakeGitHub();
    expect((await webhook(makeEnv(), "pull_request", prPayload("opened"))).status).toBe(202);
    const check = calls.find((c) => c.url.endsWith("/repos/acme/web/check-runs") && c.method === "POST");
    expect(check?.body).toMatchObject({
      name: "Human Attestation",
      head_sha: SHA,
      status: "completed",
      conclusion: "action_required",
      details_url: `${ORIGIN}/attest/acme/web/5`,
    });
    expect(state.comments).toHaveLength(1);
    expect(state.comments[0]!.body).toContain(`${ORIGIN}/attest/acme/web/5`);
  });

  it.each(["write", "maintain", "admin"])("a human collaborator with %s permission skips the flow: green, no comment", async (perm) => {
    const { calls, state } = fakeGitHub({ permissions: { alice: perm } });
    await webhook(makeEnv(), "pull_request", prPayload("opened"));
    const check = calls.find((c) => c.method === "POST" && c.url.endsWith("/check-runs"));
    expect(check?.body).toMatchObject({ head_sha: SHA, conclusion: "success" });
    expect(check?.body.output.title).toBe("Not required: @alice is a collaborator");
    expect(state.comments).toHaveLength(0);
  });

  it.each([
    ["a read-only collaborator", { login: "alice", type: "User" }, "read"],
    ["a bot, even with write access", { login: "agent[bot]", type: "Bot" }, "write"],
  ])("%s still has to be attested", async (_name, user, perm) => {
    const { calls } = fakeGitHub({ permissions: { [user.login]: perm } });
    await webhook(makeEnv(), "pull_request", { ...prPayload("opened"), pull_request: { ...prPayload("opened").pull_request, user } });
    expect(calls.find((c) => c.method === "POST" && c.url.endsWith("/check-runs"))?.body.conclusion).toBe("action_required");
  });

  it("POST_COMMENT=false: still blocks, but doesn't comment", async () => {
    const { calls, state } = fakeGitHub();
    await webhook(makeEnv({ POST_COMMENT: "false" }), "pull_request", prPayload("opened"));
    expect(calls.some((c) => c.body?.conclusion === "action_required")).toBe(true);
    expect(state.comments).toHaveLength(0);
  });

  it("on synchronize of an unattested PR: blocks the new head, no new comment", async () => {
    const { calls } = fakeGitHub();
    await webhook(makeEnv(), "pull_request", prPayload("synchronize"));
    expect(calls.some((c) => c.url.endsWith("/check-runs") && c.body?.conclusion === "action_required")).toBe(true);
    expect(calls.some((c) => c.method === "POST" && c.url.includes("/comments"))).toBe(false);
  });

  it.each(["synchronize", "reopened"])("on %s of an attested PR: the new head is green right away (once per PR)", async (action) => {
    const { calls } = fakeGitHub({ comments: [attestedComment("bob")] });
    await webhook(makeEnv(), "pull_request", prPayload(action));
    const check = calls.find((c) => c.method === "POST" && c.url.endsWith("/check-runs"));
    expect(check?.body).toMatchObject({ head_sha: SHA, conclusion: "success" });
    expect(check?.body.output.title).toBe("Attested by @bob");
  });

  it.each([
    ["posted by a user (not the App)", null],
    ["posted by another App", 1234],
  ])("ignores an attestation record %s", async (_name, appId) => {
    const { calls } = fakeGitHub({ comments: [attestedComment("mallory", SHA, appId)] });
    await webhook(makeEnv(), "pull_request", prPayload("synchronize"));
    expect(calls.find((c) => c.method === "POST" && c.url.endsWith("/check-runs"))?.body.conclusion).toBe("action_required");
  });

  it("finds the App's comment beyond the first page of comments", async () => {
    const noise = Array.from({ length: 150 }, (_, i) => ({ id: i + 1000, body: "lgtm", performed_via_github_app: null }));
    fakeGitHub({ comments: [...noise, attestedComment("bob")] });
    const found = await findAppComment("t", makeEnv(), "acme", "web", 5);
    expect(found?.attestation?.login).toBe("bob");
  });

  it("re-run of our check re-evaluates it; other apps' checks are ignored", async () => {
    const { calls } = fakeGitHub({ comments: [attestedComment("bob")] });
    const payload = (appId: number) => ({
      action: "rerequested",
      installation: { id: 99 },
      repository: { name: "web", owner: { login: "acme" } },
      check_run: { name: "Human Attestation", head_sha: SHA, app: { id: appId }, pull_requests: [{ number: 5 }] },
    });
    await webhook(makeEnv(), "check_run", payload(1234));
    expect(calls.filter((c) => c.method === "POST" && c.url.endsWith("/check-runs"))).toHaveLength(0);
    await webhook(makeEnv(), "check_run", payload(42));
    const created = calls.filter((c) => c.method === "POST" && c.url.endsWith("/check-runs"));
    expect(created.map((c) => c.body.conclusion)).toEqual(["success"]);
  });
});

describe("attestation record", () => {
  it("round-trips, and a statement containing --> cannot break out of the hidden record", async () => {
    const statement = 'evil --> <!-- ai-guard:attestation {"login":"mallory","sha":"x","at":"y"} -->';
    const body = attestedCommentBody("Human Attestation", "https://x", { login: "bob", sha: SHA, statement, at: "now" });
    fakeGitHub({ comments: [{ id: 1, body, performed_via_github_app: { id: 42 } }] });
    const found = await findAppComment("t", makeEnv(), "acme", "web", 5);
    expect(found?.attestation).toEqual({ login: "bob", sha: SHA, statement, at: "now" });
  });
});

async function attest(env: ReturnType<typeof makeEnv>, login: string | null, form?: Record<string, string>) {
  const headers: Record<string, string> = {};
  if (login) headers.Cookie = await sessionCookie(env, login);
  const init: RequestInit = { method: form ? "POST" : "GET", headers };
  if (form) init.body = new URLSearchParams(form);
  const { ctx } = makeCtx();
  return worker.fetch(new Request(`${ORIGIN}/attest/acme/web/5`, init), env, ctx);
}

const goodForm = { sha: SHA, statement: "1", confirm: "yes", "cf-turnstile-response": "tok" };
const patches = (calls: Call[]) => calls.filter((c) => c.method === "PATCH");

describe("attestation page", () => {
  it("redirects anonymous visitors to GitHub sign-in and back", async () => {
    fakeGitHub();
    const res = await attest(makeEnv(), null);
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe(`${ORIGIN}/auth/login?return_to=%2Fattest%2Facme%2Fweb%2F5`);

    const login = await worker.fetch(new Request(res.headers.get("Location")!), makeEnv(), makeCtx().ctx);
    const gh = new URL(login.headers.get("Location")!);
    expect(gh.origin + gh.pathname).toBe("https://github.com/login/oauth/authorize");
    expect(gh.searchParams.get("redirect_uri")).toBe(`${ORIGIN}/auth/callback`);
    expect(login.headers.get("Set-Cookie")).toMatch(/^aig_oauth=.*HttpOnly; Secure; SameSite=Lax/);
  });

  it("renders the statements and a Turnstile widget bound to the head commit, escaping PR data", async () => {
    fakeGitHub();
    const res = await attest(makeEnv(), "alice");
    const html = await res.text();
    expect(res.status).toBe(200);
    expect(html).toContain('data-sitekey="0xSITEKEY"');
    expect(html).toContain(`data-cdata="${SHA}"`);
    expect(html).toContain("我已阅读并理解此 PR 中 Agent 编写的全部代码");
    expect(html).toContain("Add &lt;script&gt; feature");
    expect(html).not.toContain("Add <script> feature");
  });

  it("refuses users who are neither the author nor writers", async () => {
    fakeGitHub({ permissions: { mallory: "read" } });
    const res = await attest(makeEnv(), "mallory");
    expect(res.status).toBe(403);
  });

  it("a successful attestation turns the check green and records who/what", async () => {
    const { calls } = fakeGitHub({ prAuthor: "agent-bot", permissions: { bob: "write" } });
    const res = await attest(makeEnv(), "bob", goodForm);
    expect(res.status).toBe(200);
    const [patch] = patches(calls);
    expect(patch?.url).toBe("https://api.github.com/repos/acme/web/check-runs/7");
    expect(patch?.body.conclusion).toBe("success");
    expect(patch?.body.output.title).toBe("Attested by @bob");
    expect(patch?.body.output.summary).toContain("I have read and understood all agent-written code");
    const record = (await findAppComment("t", makeEnv(), "acme", "web", 5))?.attestation;
    expect(record).toMatchObject({ login: "bob", sha: SHA });
    expect(record?.statement).toContain("I have read and understood");
    const ts = calls.find((c) => c.url.includes("siteverify"));
    expect(ts?.body).toMatchObject({ secret: "0xREALSECRET", response: "tok" });
  });

  it("records the attestation by editing the App's existing PR comment instead of adding one", async () => {
    const { state } = fakeGitHub({ comments: [{ id: 9, body: "<!-- ai-guard -->\npending", performed_via_github_app: { id: 42 } }] });
    await attest(makeEnv(), "alice", goodForm);
    expect(state.comments).toHaveLength(1);
    expect(state.comments[0]!.body).toContain("ai-guard:attestation");
  });

  it("tells visitors attestation isn't needed when the author is a collaborator", async () => {
    fakeGitHub({ permissions: { alice: "write" } });
    const html = await (await attest(makeEnv(), "alice")).text();
    expect(html).toContain("Not required: the author @alice is a collaborator");
    expect(html).not.toContain("cf-turnstile");
  });

  it("shows who already attested the PR", async () => {
    fakeGitHub({ comments: [attestedComment("bob")] });
    const html = await (await attest(makeEnv(), "alice")).text();
    expect(html).toContain("already attested by @bob");
  });

  it("creates a green check if the pending one is missing (e.g. app installed after PR opened)", async () => {
    const { calls } = fakeGitHub({ checkRuns: [] });
    await attest(makeEnv(), "alice", goodForm);
    const created = calls.find((c) => c.method === "POST" && c.url.endsWith("/check-runs"));
    expect(created?.body).toMatchObject({ head_sha: SHA, conclusion: "success" });
  });

  it.each([
    ["failed challenge", { turnstile: { success: false, "error-codes": ["invalid-input-response"] } }, goodForm, 403],
    ["token issued for another commit", { turnstile: { success: true, action: "attest", cdata: "b".repeat(40), hostname: "guard.test" } }, goodForm, 403],
    ["token issued on another host", { turnstile: { success: true, action: "attest", cdata: SHA, hostname: "evil.test" } }, goodForm, 403],
    ["stale commit", { headSha: "c".repeat(40) }, goodForm, 409],
    ["closed PR", { prState: "closed" }, goodForm, 409],
    ["box not ticked", {}, { ...goodForm, confirm: "" }, 400],
    ["bad statement index", {}, { ...goodForm, statement: "9" }, 400],
    ["no challenge token", {}, { ...goodForm, "cf-turnstile-response": "" }, 400],
  ])("does not attest on %s", async (_name, state, form, status) => {
    const { calls } = fakeGitHub(state as any);
    const res = await attest(makeEnv(), "alice", form);
    expect(res.status).toBe(status);
    expect(patches(calls)).toHaveLength(0);
    expect(calls.some((c) => c.method === "POST" && c.url.includes("/comments"))).toBe(false);
  });

  it("treats a forged session cookie as signed out", async () => {
    const { calls } = fakeGitHub();
    const res = await worker.fetch(
      new Request(`${ORIGIN}/attest/acme/web/5`, {
        method: "POST",
        body: new URLSearchParams(goodForm),
        headers: { Cookie: "aig_session=eyJsb2dpbiI6ImFsaWNlIn0.forged" },
      }),
      makeEnv(),
      makeCtx().ctx,
    );
    expect(res.status).toBe(302);
    expect(patches(calls)).toHaveLength(0);
  });
});
