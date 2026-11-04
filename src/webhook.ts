import { checkName, postComment, publicOrigin, type Env } from "./config";
import { verifyWebhookSignature } from "./crypto";
import { collaboratorPermission, enc, getPull, gh, installationToken, isWriter } from "./github";
import { findAppComment, pendingCommentBody, type Attestation } from "./record";

interface RepoRef {
  name: string;
  owner: { login: string };
}

export function attestUrl(origin: string, owner: string, repo: string, number: number): string {
  return `${origin}/attest/${enc(owner)}/${enc(repo)}/${number}`;
}

export type CheckState =
  | { kind: "exempt"; login: string; permission: string }
  | { kind: "attested"; attestation: Attestation }
  | { kind: "pending" };

/**
 * Put the check on a commit: green if the author is a collaborator or the PR was already attested
 * (once per PR), otherwise a blocking `action_required` check linking to the attestation page.
 */
export async function syncCheck(
  env: Env,
  token: string,
  origin: string,
  owner: string,
  repo: string,
  sha: string,
  number: number,
  state: CheckState,
): Promise<void> {
  const url = attestUrl(origin, owner, repo, number);
  const base = { name: checkName(env), head_sha: sha, status: "completed", details_url: url };
  let result: { conclusion: string; output: { title: string; summary: string } };
  if (state.kind === "exempt") {
    result = {
      conclusion: "success",
      output: {
        title: `Not required: @${state.login} is a collaborator`,
        summary: `The PR author @${state.login} has \`${state.permission}\` permission on this repository, so no human attestation is required.`,
      },
    };
  } else if (state.kind === "attested") {
    const a = state.attestation;
    result = {
      conclusion: "success",
      output: {
        title: `Attested by @${a.login}`,
        summary: `This PR was attested once by @${a.login} at commit \`${a.sha.slice(0, 7)}\` (${a.at}).\n\n> ${a.statement}`,
      },
    };
  } else {
    result = {
      conclusion: "action_required",
      output: {
        title: "Waiting for a human to attest",
        summary:
          `A human must confirm this PR once before it can be merged.\n\n` +
          `👉 **[Open the attestation page](${url})** — sign in with GitHub, pass the Cloudflare challenge, and confirm.`,
      },
    };
  }
  await gh(token, "POST", `/repos/${enc(owner)}/${enc(repo)}/check-runs`, { ...base, ...result });
}

/**
 * Human collaborators who can push are trusted and skip the flow. Bot accounts never do, even with
 * write access: an agent running under a bot account is exactly what this check is meant to catch.
 */
async function exemptAuthor(
  token: string,
  owner: string,
  repo: string,
  author: { login: string; type: string },
): Promise<CheckState | null> {
  if (author.type !== "User") return null;
  const permission = await collaboratorPermission(token, owner, repo, author.login);
  return isWriter(permission) ? { kind: "exempt", login: author.login, permission } : null;
}

/** Decide the PR's state and sync the check on `sha`. Creates the pending comment on PR open. */
async function refresh(
  env: Env,
  token: string,
  origin: string,
  owner: string,
  repo: string,
  sha: string,
  number: number,
  author: { login: string; type: string },
  commentIfMissing: boolean,
): Promise<void> {
  const exempt = await exemptAuthor(token, owner, repo, author);
  if (exempt) {
    await syncCheck(env, token, origin, owner, repo, sha, number, exempt);
    return;
  }
  const comment = await findAppComment(token, env, owner, repo, number);
  const state: CheckState = comment?.attestation ? { kind: "attested", attestation: comment.attestation } : { kind: "pending" };
  await syncCheck(env, token, origin, owner, repo, sha, number, state);
  if (!comment && commentIfMissing && postComment(env)) {
    await gh(token, "POST", `/repos/${enc(owner)}/${enc(repo)}/issues/${number}/comments`, {
      body: pendingCommentBody(checkName(env), attestUrl(origin, owner, repo, number)),
    });
  }
}

export async function handleWebhook(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const body = await request.text();
  if (!(await verifyWebhookSignature(env.GITHUB_WEBHOOK_SECRET, body, request.headers.get("X-Hub-Signature-256")))) {
    return new Response("invalid signature", { status: 401 });
  }
  const event = request.headers.get("X-GitHub-Event");
  const payload = JSON.parse(body);
  const origin = publicOrigin(env, request);

  const work = dispatch(env, origin, event, payload).catch((e) => console.error(`webhook ${event} failed`, e));
  // Ack quickly (GitHub times out after 10s); finish the API calls in the background.
  ctx.waitUntil(work);
  return new Response("ok", { status: 202 });
}

async function dispatch(env: Env, origin: string, event: string | null, p: any): Promise<void> {
  const installationId: number | undefined = p.installation?.id;
  if (!installationId) return;
  const repo: RepoRef | undefined = p.repository;
  if (!repo) return;
  const owner = repo.owner.login;
  const name = repo.name;

  if (event === "pull_request" && ["opened", "reopened", "synchronize"].includes(p.action)) {
    const token = await installationToken(env, installationId);
    const pr = p.pull_request;
    await refresh(env, token, origin, owner, name, pr.head.sha, pr.number, pr.user, p.action === "opened");
    return;
  }

  // "Re-run" on our check re-evaluates it (e.g. if a push raced with the attestation).
  const rerun =
    (event === "check_run" && p.action === "rerequested" && String(p.check_run?.app?.id) === String(env.GITHUB_APP_ID) &&
      p.check_run.name === checkName(env) && p.check_run) ||
    (event === "check_suite" && p.action === "rerequested" && String(p.check_suite?.app?.id) === String(env.GITHUB_APP_ID) &&
      p.check_suite);
  if (rerun) {
    const token = await installationToken(env, installationId);
    for (const pr of rerun.pull_requests ?? []) {
      const full = await getPull(token, owner, name, pr.number);
      await refresh(env, token, origin, owner, name, rerun.head_sha, pr.number, full.user, false);
    }
  }
}
