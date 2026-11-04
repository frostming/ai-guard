# AI Guard — PR 人类确认（Human Attestation）

> **AI Guard** is a serverless GitHub App, running on Cloudflare Workers, that requires a human to sign off on a pull request before it can merge.
> When a PR opens, the app adds a `Human Attestation` check that starts out blocked.
> A person signs in with GitHub, passes a Cloudflare Turnstile challenge, and confirms a short statement. For example, *"I confirm the code in this PR was written by a human"* or *"I have read and understood all agent-written code in this PR."*
> The check then turns green and stays green for later pushes, since each PR needs only one attestation.
> PRs from human collaborators with write access skip the flow. Bot accounts never do.
> The Worker keeps no database: the state lives in the check run and in a comment the app posts on the PR.

一个跑在 **Cloudflare Workers** 上的 **GitHub App**：每个 PR 会被挂上一个 `Human Attestation` Check，
初始为 `action_required`（红）。**每个 PR 只需确认一次**；**PR 作者若是有 write / maintain / admin 权限的协作者（人类账号），直接通过，无需此流程**。其他 PR 必须由一个真人：

1. 用 GitHub 登录（确认身份，且必须是 PR 作者或有 write 权限的协作者，可配置），
2. 通过 **Cloudflare Turnstile** 人机挑战，
3. 选择一条声明并勾选确认，例如
   - *I confirm the code in this PR was written by a human. / 我确认此 PR 中的代码均由人类编写。*
   - *I have read and understood all agent-written code in this PR. / 我已阅读并理解此 PR 中 Agent 编写的全部代码。*

之后该 Check 变绿，之后再 push 的 commit 也会直接是绿的。Check 详情和 PR 评论里记录了谁、何时、在哪个 commit 时、做了哪条声明。把它设为 required status check 即可阻止未确认的 PR 合并。

## 为什么是 GitHub App 而不是 Actions Workflow

- 需要一个网页让人点击 + 跑 Turnstile，Workflow 无法“挂起等待人点击”，只能轮询或手动重跑。
- App 直接创建/更新 Check Run，状态就存在 GitHub 上，**无需数据库**，Worker 完全无状态：
  “该 PR 已确认”这条记录存在 App 自己发的那条 PR 评论里（隐藏的 HTML 注释）。App 发的评论带有
  `performed_via_github_app` 标识，普通用户无法伪造，强推或 webhook 丢失也不影响。
- Check Run 绑定了 App 身份：在分支保护里把来源限定为本 App 后，其他 workflow 或 App 无法伪造同名 Check。

## 流程

```
PR opened / synchronize / reopened ──webhook──▶ Worker ──▶ 查作者权限，再查 App 的 PR 评论里有没有确认记录
                                                     ├─ 作者是有写权限的人类协作者 ──▶ Check Run: success（豁免）
                                                     ├─ 有 ──▶ 新 head 的 Check Run: success
                                                     └─ 无 ──▶ Check Run: action_required (details_url = 确认页)
                                                              └▶ PR 评论，附确认链接（仅 opened 时）
人点击链接 ──▶ GitHub OAuth 登录 ──▶ 确认页（PR 信息 + 声明 + Turnstile）
提交 ──▶ siteverify（校验 action / cData=commit SHA / hostname）
     ──▶ 校验权限、PR 仍 open、head SHA 未变
     ──▶ 写入/更新 App 的 PR 评论（确认记录）──▶ 当前 head 的 Check Run → success
```

每个 PR 确认一次即可，后续 push 自动通过。在 Check 上点 “Re-run” 会按记录重新判断（比如 push 恰好和确认同时发生时）。
协作者豁免看的是 PR 作者在事件发生时的权限：Bot 账号（如 `xxx[bot]`）即使有写权限也不豁免，因为这正是要拦的 Agent；
只读协作者也不豁免。作者权限变化后，下次 push 或 Re-run 会按新权限判断。
删除 App 的那条 PR 评论即撤销确认，下次 push 或 Re-run 时会重新要求确认。

## 部署

### 1. 部署 Worker（拿到 URL）

```bash
npm install
npx wrangler deploy        # 得到 https://ai-guard.<you>.workers.dev
```

### 2. 创建 Turnstile 组件

Cloudflare Dashboard → Turnstile → Add widget，Hostname 填 Worker 的域名，模式选 Managed。
记下 **Site Key**（填进 `wrangler.jsonc` 的 `TURNSTILE_SITE_KEY`）和 **Secret Key**。

### 3. 创建 GitHub App

GitHub → Settings → Developer settings → GitHub Apps → New：

| 项 | 值 |
|---|---|
| Homepage URL | `https://<worker>/` |
| Callback URL | `https://<worker>/auth/callback` |
| Webhook URL | `https://<worker>/webhook` |
| Webhook secret | 随机字符串 |
| Repository permissions | **Checks: Read & write**，**Pull requests: Read & write**，Metadata: Read |
| Subscribe to events | **Pull request**，**Check run** |

创建后记下 App ID、Client ID，生成 Client secret，生成并下载 private key（`.pem`，PKCS#1 格式可直接用）。

### 4. 配置

在 `wrangler.jsonc` 填 `GITHUB_APP_ID`、`GITHUB_CLIENT_ID`、`TURNSTILE_SITE_KEY`，然后：

```bash
npx wrangler secret put GITHUB_APP_PRIVATE_KEY < your-app.private-key.pem
npx wrangler secret put GITHUB_WEBHOOK_SECRET
npx wrangler secret put GITHUB_CLIENT_SECRET
npx wrangler secret put TURNSTILE_SECRET_KEY
openssl rand -base64 32 | npx wrangler secret put SESSION_SECRET
npx wrangler deploy
```

### 5. 安装并设为必需检查

把 App 安装到目标仓库/组织。然后在仓库 Settings → Rules（或 Branch protection）里，
Require status checks → 添加 `Human Attestation`，**来源选择你的这个 App**。

### 6. 自动部署（可选）

`.github/workflows/ci.yml`：每次 push / PR 都跑类型检查和测试；push 到 `main` 且测试通过后自动 `wrangler deploy`。
需要在仓库 Secrets 里配置 `CLOUDFLARE_API_TOKEN`（需有 Workers Scripts 编辑权限）和 `CLOUDFLARE_ACCOUNT_ID`。
部署只更新代码和 `wrangler.jsonc` 里的 vars，Worker 上已设置的 secrets 保持不变。

## 配置项（`vars`）

| 变量 | 默认 | 说明 |
|---|---|---|
| `CHECK_NAME` | `Human Attestation` | Check 名称（分支保护里要求的名字） |
| `ATTESTER_POLICY` | `author_or_writers` | `author`：仅 PR 作者；`writers`：仅有 write/maintain/admin 权限者；`author_or_writers`：两者皆可。PR 作者是 bot 时需要有写权限的人来确认 |
| `POST_COMMENT` | `true` | PR 打开时是否评论确认链接（关掉后，确认时仍会发一条评论作为记录） |
| `STATEMENTS` | 中英双语两条 | JSON 字符串数组，自定义可选声明 |
| `PUBLIC_URL` | 请求的 origin | 绑定自定义域名时设置 |

## 本地开发

```bash
cp .dev.vars.example .dev.vars   # 内含 Turnstile 测试 key（总是通过）
npm run dev
npm test                          # 单元 + 端到端（mock GitHub / Turnstile）
```

webhook 可用 `cloudflared tunnel --url http://localhost:8787` 暴露给 GitHub。

## 安全说明

- Webhook 用 `X-Hub-Signature-256` HMAC 校验；会话/OAuth state 为 HMAC 签名的 HttpOnly、Secure、SameSite=Lax cookie，会话 1 小时过期。
- Turnstile token 校验 `action=attest`、`cData=<head SHA>`、`hostname`，防止跨页面/跨 commit 复用。
- 只信任本 App 创建的 Check Run（按 `app_id` 过滤）和本 App 发的评论（按 `performed_via_github_app.id` 过滤）；记录里的 `--` 会被转义，声明文本无法提前结束隐藏注释。
- GitHub 用户 token 仅用于识别身份，不保存。
- 仓库管理员仍可绕过分支保护，也能编辑 App 的评论——这是 GitHub 本身的权限模型。
