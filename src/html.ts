export function esc(s: unknown): string {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

const CSS = `
:root{color-scheme:light dark;--bg:#f6f8fa;--card:#fff;--fg:#1f2328;--muted:#59636e;--border:#d1d9e0;--accent:#1f883d;--warn:#9a6700;--err:#d1242f}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--card:#151b23;--fg:#f0f6fc;--muted:#9198a1;--border:#3d444d;--accent:#2ea043;--warn:#d29922;--err:#f85149}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans",Helvetica,Arial,sans-serif}
main{max-width:640px;margin:48px auto;padding:0 16px}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:28px}
h1{font-size:20px;margin:0 0 4px}.muted{color:var(--muted)}a{color:inherit}
.pr{border:1px solid var(--border);border-radius:8px;padding:12px 14px;margin:18px 0}
.pr b{word-break:break-word}.stats{font-size:13px}.add{color:var(--accent)}.del{color:var(--err)}
fieldset{border:0;padding:0;margin:18px 0}legend{font-weight:600;margin-bottom:8px}
label.opt{display:flex;gap:10px;align-items:flex-start;border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin:8px 0;cursor:pointer}
label.opt:has(input:checked){border-color:var(--accent);box-shadow:0 0 0 1px var(--accent)}
input[type=radio],input[type=checkbox]{margin-top:4px}
.note{font-size:13px;margin-top:-6px}
button{background:var(--accent);color:#fff;border:0;border-radius:8px;padding:10px 18px;font-size:15px;font-weight:600;cursor:pointer}
button:disabled{opacity:.5;cursor:not-allowed}
.banner{border-radius:8px;padding:12px 14px;margin:14px 0;border:1px solid}
.ok{border-color:var(--accent)}.warn{border-color:var(--warn)}.err{border-color:var(--err)}
.who{display:flex;justify-content:space-between;font-size:13px;margin-top:20px}
`;

export function page(title: string, body: string, status = 200, extraHead = ""): Response {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><style>${CSS}</style>${extraHead}</head><body><main><div class="card">${body}</div></main></body></html>`;
  return new Response(html, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "same-origin",
      "Content-Security-Policy":
        "default-src 'none'; style-src 'unsafe-inline'; script-src https://challenges.cloudflare.com 'unsafe-inline'; frame-src https://challenges.cloudflare.com; connect-src https://challenges.cloudflare.com; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    },
  });
}

export function message(title: string, text: string, kind: "ok" | "warn" | "err", link?: { href: string; label: string }, status = 200): Response {
  return page(
    title,
    `<h1>${esc(title)}</h1><div class="banner ${kind}">${esc(text)}</div>${
      link ? `<p><a href="${esc(link.href)}">${esc(link.label)}</a></p>` : ""
    }`,
    status,
  );
}
