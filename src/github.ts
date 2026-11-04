import { createAppJwt, importRsaPrivateKey } from "./crypto";
import type { Env } from "./config";

const API = "https://api.github.com";
const UA = "ai-guard-human-attestation";

export class GitHubError extends Error {
  constructor(
    public status: number,
    public path: string,
    body: string,
  ) {
    super(`GitHub API ${status} on ${path}: ${body.slice(0, 300)}`);
  }
}

export async function gh<T>(token: string, method: string, path: string, body?: unknown, scheme = "Bearer"): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    method,
    headers: {
      Authorization: `${scheme} ${token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": UA,
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new GitHubError(res.status, path, await res.text());
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

// Per-isolate caches. Workers isolates are short-lived, which is fine: these are just optimizations.
let keyCache: { pem: string; key: Promise<CryptoKey> } | undefined;
const tokenCache = new Map<number, { token: string; expiresAt: number }>();

export async function appJwt(env: Env): Promise<string> {
  if (!keyCache || keyCache.pem !== env.GITHUB_APP_PRIVATE_KEY) {
    keyCache = { pem: env.GITHUB_APP_PRIVATE_KEY, key: importRsaPrivateKey(env.GITHUB_APP_PRIVATE_KEY) };
  }
  return createAppJwt(env.GITHUB_APP_ID, await keyCache.key);
}

export async function installationToken(env: Env, installationId: number): Promise<string> {
  const cached = tokenCache.get(installationId);
  if (cached && cached.expiresAt - Date.now() > 5 * 60_000) return cached.token;
  const res = await gh<{ token: string; expires_at: string }>(
    await appJwt(env),
    "POST",
    `/app/installations/${installationId}/access_tokens`,
  );
  tokenCache.set(installationId, { token: res.token, expiresAt: Date.parse(res.expires_at) });
  return res.token;
}

export async function repoInstallationId(env: Env, owner: string, repo: string): Promise<number> {
  const res = await gh<{ id: number }>(await appJwt(env), "GET", `/repos/${enc(owner)}/${enc(repo)}/installation`);
  return res.id;
}

const WRITE_PERMS = new Set(["admin", "maintain", "write"]);

/** Collaborators who can push (write / maintain / admin). */
export function isWriter(permission: string): boolean {
  return WRITE_PERMS.has(permission);
}

export function enc(s: string): string {
  return encodeURIComponent(s);
}

export interface PullRequest {
  number: number;
  title: string;
  state: string;
  html_url: string;
  user: { login: string; type: string };
  head: { sha: string };
  additions: number;
  deletions: number;
  changed_files: number;
}

export interface CheckRun {
  id: number;
  head_sha: string;
  status: string;
  conclusion: string | null;
  app: { id: number } | null;
}

export async function getPull(token: string, owner: string, repo: string, number: number): Promise<PullRequest> {
  return gh<PullRequest>(token, "GET", `/repos/${enc(owner)}/${enc(repo)}/pulls/${number}`);
}

export async function collaboratorPermission(token: string, owner: string, repo: string, login: string): Promise<string> {
  try {
    const res = await gh<{ permission: string }>(
      token,
      "GET",
      `/repos/${enc(owner)}/${enc(repo)}/collaborators/${enc(login)}/permission`,
    );
    return res.permission; // admin | maintain | write | triage | read | none
  } catch (e) {
    if (e instanceof GitHubError && e.status === 404) return "none";
    throw e;
  }
}

export async function listOurCheckRuns(
  token: string,
  env: Env,
  owner: string,
  repo: string,
  sha: string,
  name: string,
): Promise<CheckRun[]> {
  const q = new URLSearchParams({ check_name: name, app_id: env.GITHUB_APP_ID, filter: "all", per_page: "100" });
  const res = await gh<{ check_runs: CheckRun[] }>(
    token,
    "GET",
    `/repos/${enc(owner)}/${enc(repo)}/commits/${enc(sha)}/check-runs?${q}`,
  );
  // Belt and braces: never touch a check run another app created with the same name.
  return res.check_runs.filter((c) => String(c.app?.id) === String(env.GITHUB_APP_ID));
}
