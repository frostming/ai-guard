// The PR-level attestation record lives in a single comment posted by this App.
// Comments made by a GitHub App carry `performed_via_github_app`, which users cannot forge,
// so the Worker stays stateless and the record survives force-pushes and missed webhooks.

import type { Env } from "./config";
import { enc, gh } from "./github";

const MARKER = "<!-- ai-guard -->";
const RECORD_RE = /<!-- ai-guard:attestation (\{.*?\}) -->/;

export interface Attestation {
  login: string;
  sha: string;
  statement: string;
  at: string;
}

interface IssueComment {
  id: number;
  body?: string;
  performed_via_github_app?: { id: number } | null;
}

export interface AppComment {
  id: number;
  attestation: Attestation | null;
}

function parseRecord(body: string): Attestation | null {
  const m = RECORD_RE.exec(body);
  if (!m) return null;
  try {
    const r = JSON.parse(m[1]!) as Partial<Attestation>;
    return typeof r.login === "string" && typeof r.sha === "string" && typeof r.at === "string"
      ? { login: r.login, sha: r.sha, at: r.at, statement: String(r.statement ?? "") }
      : null;
  } catch {
    return null;
  }
}

/** Find this App's comment on the PR (if any) and the attestation recorded in it. */
export async function findAppComment(token: string, env: Env, owner: string, repo: string, number: number): Promise<AppComment | null> {
  for (let page = 1; page <= 30; page++) {
    const comments = await gh<IssueComment[]>(
      token,
      "GET",
      `/repos/${enc(owner)}/${enc(repo)}/issues/${number}/comments?per_page=100&page=${page}`,
    );
    const ours = comments.find(
      (c) => String(c.performed_via_github_app?.id) === String(env.GITHUB_APP_ID) && c.body?.includes(MARKER),
    );
    if (ours) return { id: ours.id, attestation: parseRecord(ours.body ?? "") };
    if (comments.length < 100) return null;
  }
  return null;
}

export function pendingCommentBody(checkName: string, url: string): string {
  return (
    `${MARKER}\n🛡️ **${checkName} required.** A human needs to confirm this PR once before it can merge.\n\n` +
    `[Attest this PR](${url}) — sign in with GitHub, pass the challenge, and confirm one of the statements.`
  );
}

export function attestedCommentBody(checkName: string, url: string, a: Attestation): string {
  // Escape "-->" so a statement can never terminate the HTML comment early.
  const record = JSON.stringify(a).replace(/--/g, "\\u002d\\u002d");
  return (
    `${MARKER}\n<!-- ai-guard:attestation ${record} -->\n` +
    `✅ **${checkName}:** @${a.login} attested this PR at commit \`${a.sha.slice(0, 7)}\` (${a.at}).\n\n` +
    `> ${a.statement}\n\n` +
    `Later pushes to this PR stay attested. [Attestation page](${url})`
  );
}

export async function upsertAppComment(
  token: string,
  owner: string,
  repo: string,
  number: number,
  existing: AppComment | null,
  body: string,
): Promise<void> {
  if (existing) {
    await gh(token, "PATCH", `/repos/${enc(owner)}/${enc(repo)}/issues/comments/${existing.id}`, { body });
  } else {
    await gh(token, "POST", `/repos/${enc(owner)}/${enc(repo)}/issues/${number}/comments`, { body });
  }
}
