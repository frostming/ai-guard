import { showAttestPage, submitAttestation } from "./attest";
import { callback, login, logout } from "./auth";
import { checkName, type Env } from "./config";
import { esc, message, page } from "./html";
import { handleWebhook } from "./webhook";

const ATTEST_RE = /^\/attest\/([^/]+)\/([^/]+)\/(\d+)$/;

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const { pathname } = url;
    const method = request.method;
    try {
      if (pathname === "/webhook" && method === "POST") return await handleWebhook(request, env, ctx);
      if (pathname === "/auth/login" && method === "GET") return await login(request, env);
      if (pathname === "/auth/callback" && method === "GET") return await callback(request, env);
      if (pathname === "/auth/logout" && method === "GET") return logout();
      if (pathname === "/healthz") return new Response("ok");

      const m = ATTEST_RE.exec(pathname);
      if (m) {
        const owner = decodeURIComponent(m[1]!);
        const repo = decodeURIComponent(m[2]!);
        const number = Number(m[3]);
        if (method === "GET") return await showAttestPage(request, env, owner, repo, number);
        if (method === "POST") return await submitAttestation(request, env, owner, repo, number);
        return new Response("method not allowed", { status: 405 });
      }

      if (pathname === "/" && method === "GET") {
        return page(
          "AI Guard",
          `<h1>AI Guard — ${esc(checkName(env))}</h1><p class="muted">A GitHub App that blocks pull requests until a signed-in human passes a Cloudflare Turnstile challenge and attests to the code. Open the link from a PR's check to attest.</p>`,
        );
      }
      return new Response("not found", { status: 404 });
    } catch (e) {
      console.error("unhandled", e);
      return message("Something went wrong", "An unexpected error occurred. Please try again.", "err", undefined, 500);
    }
  },
} satisfies ExportedHandler<Env>;
