export interface Env {
  // --- vars (wrangler.jsonc) ---
  GITHUB_APP_ID: string;
  GITHUB_CLIENT_ID: string;
  TURNSTILE_SITE_KEY: string;
  /** Check run name; this is what you mark as "required" in branch protection / rulesets. */
  CHECK_NAME?: string;
  /** "author" | "writers" | "author_or_writers" (default). Who may attest a PR. */
  ATTESTER_POLICY?: string;
  /** "true" (default) to post a PR comment with the attestation link when a PR is opened. */
  POST_COMMENT?: string;
  /** Optional JSON array of statements a human may choose from. */
  STATEMENTS?: string;
  /** Optional public origin, e.g. https://ai-guard.example.com. Defaults to the request origin. */
  PUBLIC_URL?: string;

  // --- secrets (wrangler secret put) ---
  GITHUB_APP_PRIVATE_KEY: string;
  GITHUB_WEBHOOK_SECRET: string;
  GITHUB_CLIENT_SECRET: string;
  TURNSTILE_SECRET_KEY: string;
  SESSION_SECRET: string;
}

export const DEFAULT_STATEMENTS = [
  "I confirm the code in this PR was written by a human. / 我确认此 PR 中的代码均由人类编写。",
  "I have read and understood all agent-written code in this PR. / 我已阅读并理解此 PR 中 Agent 编写的全部代码。",
];

export type AttesterPolicy = "author" | "writers" | "author_or_writers";

export function checkName(env: Env): string {
  return env.CHECK_NAME?.trim() || "Human Attestation";
}

export function attesterPolicy(env: Env): AttesterPolicy {
  const p = env.ATTESTER_POLICY?.trim();
  return p === "author" || p === "writers" ? p : "author_or_writers";
}

export function statements(env: Env): string[] {
  if (!env.STATEMENTS) return DEFAULT_STATEMENTS;
  try {
    const parsed: unknown = JSON.parse(env.STATEMENTS);
    if (Array.isArray(parsed) && parsed.length > 0 && parsed.every((s) => typeof s === "string" && s.trim())) {
      return parsed as string[];
    }
  } catch {
    // fall through
  }
  console.warn("STATEMENTS is not a non-empty JSON array of strings; using defaults");
  return DEFAULT_STATEMENTS;
}

export function publicOrigin(env: Env, request: Request): string {
  return (env.PUBLIC_URL?.trim() || new URL(request.url).origin).replace(/\/+$/, "");
}

export function postComment(env: Env): boolean {
  return (env.POST_COMMENT ?? "true").toLowerCase() !== "false";
}
