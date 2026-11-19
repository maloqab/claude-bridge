# claude-bridge

Lets your Grok Bots hand repository work to Claude Code on an always-on Mac, privately over Tailscale, and lets Claude Code message any of your bots and get answers. **Setting it up: [docs/SETUP.md](docs/SETUP.md)** (hand it to your agent).

> Community project, not affiliated with or endorsed by Anthropic or xAI. Claude and Claude Code are Anthropic's; Grok Bot is xAI's. Provided as is under the [MIT license](LICENSE) and maintained on a best-effort basis. Report security issues privately: see [SECURITY.md](SECURITY.md).

```
Grok Bot ──MCP over tailnet──▶ claude-bridge (bridge Mac) ──▶ claude -p in a locked-down worktree
   ▲                                   │
   └──── Grok webhook routine ◀────────┘  (pointer only: job id + status)
```


## Tools (MCP, Streamable HTTP, JSON responses)

| Tool | What it does |
|---|---|
| `delegate_to_claude(repo, task, mode, pr?, notify?, hop?)` | Starts a background job and returns `job_id`. `review` mode reads only; `work` mode edits files on its own branch. With `pr` (review mode only), the bridge checks out that pull request's head and puts the diff in `.claude-bridge/pr-<n>.diff`, because Claude has no shell to run `git diff`. |
| `resume_claude(job_id, message, notify?, hop?)` | Continues a finished job's Claude session, with the same branch and context. |
| `check_job(job_id)` | Returns status, Claude's summary, branch, diff stat, and the draft PR link. |
| `list_jobs(limit?)` | Lists recent jobs. |
| `message_claude(message, reply_to?)` | Sends Claude Code a message (a reply, question or status). It lands in `~/.claude-bridge/inbox/claude-code.jsonl`, and a watching Claude Code session wakes on it right away. It starts no job. Limit: 30 per hour. |

**Talking to any bot from a Claude Code session:** `bot <name> "<message>" [--wait 600]` (`deploy/bot`) works on any of your Macs; it runs `bridge.py send`. A bot with its own webhook in `notify` gets the message directly. Every other bot gets it relayed by the `relay_via` bot, bot to bot. The bot answers with `message_claude(message, reply_to=<ping_id>, from_bot=<name>)`. With `--wait`, the answer prints in the session; otherwise it shows at the start of the next one.

`python3 bridge.py notify <target> "<message>"` is the older name for `send`. It reads the webhook URL and key from 1Password at call time. Each ping carries a `ping_id`; the bot answers with `message_claude(..., reply_to=ping_id)`.

A session can watch the inbox live with `ssh <bridge-mac> 'tail -n0 -F ~/.claude-bridge/inbox/claude-code.jsonl'`; `deploy/inbox_hook.py` shows unread messages when a session starts.

## Automatic PR reviews

With a `pr_review` block in the config, the service also reviews pull requests on its own. Every 3 minutes it lists open PRs with `gh`. When a PR's head has been stable for 2 minutes, it runs a review-mode job on that head. Drafts and dependabot are skipped, and each PR gets at most 4 reviews a day. The result is posted as a GitHub review: a summary, a confidence score (1-5), and findings, which become inline comments when their line is in the diff. A **Claude Review** commit status shows pending, success, or failure when something blocks merging. Posts use the mini's `gh` login, and the Claude token stays in 1Password.

```json
"pr_review": {"repos": {"my-repo": "my-org/my-repo"}, "interval_s": 180, "settle_s": 120, "max_per_pr_per_day": 4}
```

**`@claude` replies.** Mention `@claude` in a review thread or in the PR conversation and the bridge reacts 👀. It then runs a read-only job on the PR head, with the thread as context, and replies in the same thread. Only authors in `mention_authors` (default: the bridge Mac's `gh` login) can trigger it, at most `max_mentions_per_hour` (default 10). Bridge comments carry a hidden `<!-- claude-bridge -->` marker so Claude never answers itself. On first start it only answers comments posted from then on.

Each repo key must also be in `repos`. State lives in `~/.claude-bridge/pr-review.json`; delete an entry there to force a re-review.

## Security model

Every point below was tested against Claude Code 2.1.325 on the mini.

- **Who can call:** a request needs the bearer token (`token_ref`) **and** must come from a tailnet device in `allowed_callers`, checked with `tailscale whois`. The server listens only on the mini's tailnet IP.
- **What a job can do:**
  - `--tools` fixes the toolset: `Read,Grep,Glob` for review; review plus `Edit,Write` for work. A job has no Bash, no web and no subagents.
  - `--permission-mode dontAsk` denies anything not explicitly allowed. Reads are confined to the job's worktree, so `~/.zshrc` and `~/.config/op/` are denied. Work mode allows `Edit(/<worktree>/**)` only.
  - `--setting-sources ""`, `disableAllHooks` and `--strict-mcp-config` stop user and project settings, hooks and MCP servers from loading. A repo's `.claude/settings.json` or `.mcp.json` therefore can't take over a job.
  - Bypass permission modes are never used.
- **Git:** the bridge commits, pushes and opens **draft** PRs. Claude never touches git. PRs need a human or agent to mark them ready.
- **Limits:** one job at a time, `max_jobs_per_hour` per caller, `max_hops` against bot↔Claude loops, and `job_timeout_s`.
- **Webhooks:** they carry a pointer (job id and status), never output. The bot fetches the result with `check_job`. The `notify` CLI refuses messages over 3,500 characters, because Grok keeps only about 4,000.
- **Secrets:** read at runtime from `op://` (1Password CLI), `env:` or `file:` references, and never written to config, logs or job files.

Logs and state live in `~/.claude-bridge/`: `jobs/`, `logs/`, `work/` (one worktree per job), `repos/` (bridge-owned clones) and `access.log`.

## Install

See [docs/SETUP.md](docs/SETUP.md). It's written so you can hand it to your coding agent, with the steps that need you marked **[HUMAN]**.

## Tests

```
python3 -m unittest discover -s tests
```

The tests use a fake `claude` binary, a temporary git remote and a local webhook receiver.
