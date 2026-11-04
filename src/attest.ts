import { getSession, verifyTurnstile, type Session } from "./auth";
import { attesterPolicy, checkName, publicOrigin, statements, type AttesterPolicy, type Env } from "./config";
import {
  collaboratorPermission,
  enc,
  getPull,
  isWriter,
  gh,
  GitHubError,
  installationToken,
  listOurCheckRuns,
  repoInstallationId,
  type PullRequest,
} from "./github";
import { esc, message, page } from "./html";
import { attestedCommentBody, findAppComment, upsertAppComment } from "./record";
import { attestUrl } from "./webhook";

export function canAttest(policy: AttesterPolicy, login: string, prAuthor: string, permission: string): boolean {
  const isAuthor = login.toLowerCase() === prAuthor.toLowerCase();
  if (policy === "author") return isAuthor;
  if (policy === "writers") return isWriter(permission);
  return isAuthor || isWriter(permission);
}

function policyText(policy: AttesterPolicy): string {
  return {
    author: "the PR author",
    writers: "a collaborator with write access",
    author_or_writers: "the PR author or a collaborator with write access",
  }[policy];
}

/** Turnstile's documented test secrets don't echo action/cdata/hostname, so skip those checks for them. */
function isTurnstileTestSecret(secret: string): boolean {
  return /^[123]x0{16,}/.test(secret);
}

interface Ctx {
  owner: string;
  repo: string;
  number: number;
  session: Session;
  token: string;
  pr: PullRequest;
  permission: string;
  allowed: boolean;
}

type Loaded = { ok: true; ctx: Ctx } | { ok: false; response: Response };

async function load(request: Request, env: Env, owner: string, repo: string, number: number): Promise<Loaded> {
  const session = await getSession(request, env);
  if (!session) {
    const path = new URL(request.url).pathname;
    return { ok: false, response: Response.redirect(`${publicOrigin(env, request)}/auth/login?return_to=${encodeURIComponent(path)}`, 302) };
  }
  let token: string;
  let pr: PullRequest;
  try {
    token = await installationToken(env, await repoInstallationId(env, owner, repo));
    pr = await getPull(token, owner, repo, number);
  } catch (e) {
    if (e instanceof GitHubError && e.status === 404) {
      return { ok: false, response: message("Not found", "This pull request doesn't exist or the app isn't installed on the repository.", "err", undefined, 404) };
    }
    throw e;
  }
  const permission = await collaboratorPermission(token, owner, repo, session.login);
  const allowed = canAttest(attesterPolicy(env), session.login, pr.user.login, permission);
  return { ok: true, ctx: { owner, repo, number, session, token, pr, permission, allowed } };
}

function prCard(ctx: Ctx): string {
  const { pr } = ctx;
  return `<div class="pr"><div class="muted">${esc(ctx.owner)}/${esc(ctx.repo)} #${pr.number} · by @${esc(pr.user.login)}${
    pr.user.type === "Bot" ? " (bot)" : ""
  }</div>
<b><a href="${esc(pr.html_url)}">${esc(pr.title)}</a></b>
<div class="stats muted">commit <code>${esc(pr.head.sha.slice(0, 7))}</code> · ${pr.changed_files} files ·
<span class="add">+${pr.additions}</span> <span class="del">−${pr.deletions}</span> ·
<a href="${esc(pr.html_url)}/files">review the diff ↗</a></div></div>`;
}

function whoBar(ctx: Ctx): string {
  return `<div class="who muted"><span>Signed in as @${esc(ctx.session.login)}</span><a href="/auth/logout">Sign out</a></div>`;
}

export async function showAttestPage(request: Request, env: Env, owner: string, repo: string, number: number): Promise<Response> {
  const loaded = await load(request, env, owner, repo, number);
  if (!loaded.ok) return loaded.response;
  const { ctx } = loaded;
  const { pr } = ctx;
  const title = `Attest ${owner}/${repo}#${number}`;
  const head = `<h1>Human attestation</h1><p class="muted">This repository requires a human to confirm each pull request once before merge.</p>${prCard(ctx)}`;

  if (pr.state !== "open") return page(title, `${head}<div class="banner warn">This pull request is ${esc(pr.state)}.</div>${whoBar(ctx)}`);
  if (!ctx.allowed) {
    return page(
      title,
      `${head}<div class="banner err">@${esc(ctx.session.login)} can't attest this PR. It must be attested by ${esc(
        policyText(attesterPolicy(env)),
      )}.</div>${whoBar(ctx)}`,
      403,
    );
  }

  const authorPerm = pr.user.type === "User" ? await collaboratorPermission(ctx.token, owner, repo, pr.user.login) : "none";
  if (isWriter(authorPerm)) {
    return page(
      title,
      `${head}<div class="banner ok">Not required: the author @${esc(pr.user.login)} is a collaborator with ${esc(
        authorPerm,
      )} permission. Push a commit or re-run the check if it isn't green yet.</div>${whoBar(ctx)}`,
    );
  }

  const record = (await findAppComment(ctx.token, env, owner, repo, number))?.attestation;
  const doneBanner = record
    ? `<div class="banner ok">This PR was already attested by @${esc(record.login)} at <code>${esc(
        record.sha.slice(0, 7),
      )}</code>. Submitting again replaces that record with yours.</div>`
    : "";

  const options = statements(env)
    .map(
      (s, i) =>
        `<label class="opt"><input type="radio" name="statement" value="${i}" required><span>${esc(s)}</span></label>`,
    )
    .join("");

  const body = `${head}${doneBanner}
<form method="post" id="f">
<input type="hidden" name="sha" value="${esc(pr.head.sha)}">
<fieldset><legend>Choose the statement that is true for this pull request</legend>${options}</fieldset>
<div class="cf-turnstile" data-sitekey="${esc(env.TURNSTILE_SITE_KEY)}" data-action="attest" data-cdata="${esc(
    pr.head.sha,
  )}" data-callback="aigReady" data-expired-callback="aigExpired"></div>
<p><button type="submit" id="go" disabled>Attest as @${esc(ctx.session.login)}</button></p>
<p class="note muted">Recorded on this PR at commit <code>${esc(pr.head.sha.slice(0, 7))}</code>; later pushes stay attested.</p>
</form>${whoBar(ctx)}
<script>
function aigReady(){document.getElementById('go').disabled=false}
function aigExpired(){document.getElementById('go').disabled=true}
</script>`;

  return page(title, body, 200, `<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>`);
}

export async function submitAttestation(request: Request, env: Env, owner: string, repo: string, number: number): Promise<Response> {
  const loaded = await load(request, env, owner, repo, number);
  if (!loaded.ok) return loaded.response;
  const { ctx } = loaded;
  const { pr } = ctx;
  const back = { href: new URL(request.url).pathname, label: "← Back to the attestation page" };

  const form = await request.formData();
  const sha = String(form.get("sha") ?? "");
  const rawIdx = String(form.get("statement") ?? "");
  const idx = /^\d+$/.test(rawIdx) ? Number(rawIdx) : -1;
  const turnstileToken = String(form.get("cf-turnstile-response") ?? "");
  const all = statements(env);

  if (!Number.isInteger(idx) || idx < 0 || idx >= all.length || !turnstileToken) {
    return message("Incomplete", "Choose a statement and complete the challenge.", "err", back, 400);
  }

  if (!ctx.allowed) {
    return message("Not allowed", `Only ${policyText(attesterPolicy(env))} can attest this PR.`, "err", back, 403);
  }
  if (pr.state !== "open") return message("PR not open", `This pull request is ${pr.state}.`, "warn", back, 409);
  if (sha !== pr.head.sha) {
    return message("New commits", "The PR has new commits since you opened this page. Review them and attest again.", "warn", back, 409);
  }

  const ts = await verifyTurnstile(env, turnstileToken, request.headers.get("CF-Connecting-IP"));
  if (!ts.success) {
    return message("Challenge failed", `Cloudflare challenge failed (${(ts["error-codes"] ?? []).join(", ") || "unknown"}). Try again.`, "err", back, 403);
  }
  if (!isTurnstileTestSecret(env.TURNSTILE_SECRET_KEY)) {
    const expectedHost = new URL(publicOrigin(env, request)).hostname;
    if (ts.action !== "attest" || ts.cdata !== sha || ts.hostname !== expectedHost) {
      return message("Challenge mismatch", "The challenge token wasn't issued for this page. Reload and try again.", "err", back, 403);
    }
  }

  const statement = all[idx]!;
  const when = new Date().toISOString();
  const url = attestUrl(publicOrigin(env, request), owner, repo, number);

  // Write the PR-level record first: it's the source of truth that later pushes are checked against.
  const existing = await findAppComment(ctx.token, env, owner, repo, number);
  await upsertAppComment(
    ctx.token,
    owner,
    repo,
    number,
    existing,
    attestedCommentBody(checkName(env), url, { login: ctx.session.login, sha, statement, at: when }),
  );

  const output = {
    title: `Attested by @${ctx.session.login}`,
    summary:
      `> ${statement}\n\n` +
      `| | |\n|---|---|\n` +
      `| Attested by | @${ctx.session.login} (repo permission: ${ctx.permission}) |\n` +
      `| PR author | @${pr.user.login} |\n` +
      `| Commit | \`${pr.head.sha}\` |\n` +
      `| Time | ${when} |\n` +
      `| Verification | GitHub sign-in + Cloudflare Turnstile |`,
  };

  const runs = await listOurCheckRuns(ctx.token, env, owner, repo, sha, checkName(env));
  const base = `/repos/${enc(owner)}/${enc(repo)}/check-runs`;
  const patch = { status: "completed", conclusion: "success", completed_at: when, details_url: url, output };
  if (runs.length === 0) {
    await gh(ctx.token, "POST", base, { name: checkName(env), head_sha: sha, ...patch });
  } else {
    await Promise.all(runs.map((r) => gh(ctx.token, "PATCH", `${base}/${r.id}`, patch)));
  }

  console.log(JSON.stringify({ event: "attested", repo: `${owner}/${repo}`, pr: number, sha, login: ctx.session.login, statement: idx }));
  return message(
    "Attested ✅",
    `Thanks @${ctx.session.login}. The "${checkName(env)}" check is now green, and later pushes to this PR stay attested.`,
    "ok",
    { href: pr.html_url, label: "← Back to the pull request" },
  );
}
