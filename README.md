# tether

**Tether cloud bots to local coding agents on your Mac, both ways.**

Tether *(formerly `claude-bridge`)* is a single-file, dependency-free MCP server that runs on an always-on Mac over [Tailscale](https://tailscale.com). Cloud bots (such as Grok Bots) connect to it privately on your tailnet to delegate work in your repositories, and any local coding agent or terminal session on your Macs (Claude Code, Codex, Antigravity, OpenCode, or plain shell) can message your bots and get answers back.

```
Cloud Bot (Grok) ── MCP over Tailscale ──▶ tether ──▶ Local Coding Agents
       ▲                                     │        (Claude Code, terminal CLI, …)
       └──── webhook (job done / `bot` msg) ─┘
```

## What it does

- **Bot → Local Agent.** A cloud bot calls `delegate_to_claude` to run a headless coding job in an allowlisted repo — either `review` (read-only) or `work` (edits on a fresh branch with optional draft PR) — and inspects results with `check_job`.
- **Any Local Agent → Bot.** From any terminal or coding-agent session on any of your Macs, `bot assistant "…"` wakes a cloud bot and optionally waits for its reply via `message_claude`. Bots without their own webhook are relayed through your main bot.
- **Multi-turn conversations.** `resume_claude` continues a finished job with a follow-up in the same session and branch.
- **Private by default.** Listens only on your Tailscale IP and checks both a bearer token and the caller's Tailscale device identity on every request. Nothing is exposed to the public internet.
- **Zero dependencies.** One standard-library Python file (`bridge.py`).

> **Note on naming:** Tether was originally built as `claude-bridge`. To avoid breaking existing installs and launchd services, the default config path (`~/.config/claude-bridge/config.json`), launchd label (`ai.claude-bridge`), and current headless job tool names (`delegate_to_claude`, `resume_claude`, `message_claude`) keep their original names while broader multi-agent and live terminal session support rolls out.

## Requirements

- An always-on Mac with Python 3.9+, `git`, and [Claude Code](https://claude.com/claude-code) for delegated jobs
- [Tailscale](https://tailscale.com) on that Mac
- A cloud bot platform with MCP + Tailscale support (e.g. [Grok Bot](https://grok.com) with its Tailscale plugin connected)

## Quick start

> **Easiest:** hand [docs/SETUP.md](docs/SETUP.md) to your coding agent. It configures the Mac side and walks you through the few clicks in Grok Bot and Tailscale.

```bash
git clone https://github.com/maloqab/tether ~/claude-bridge
cd ~/claude-bridge && sh deploy/install.sh        # installs the launchd service and starter config
claude setup-token                                # token for headless delegated runs
```

1. Fill in `~/.config/claude-bridge/config.json` with your Tailscale IP, bearer token, Claude setup token, and allowlisted repos (see [Configuration](#configuration)).
2. In Grok Bot: **Connect apps → Add a custom connector → Remote HTTPS**, using `http://<your-mac>.<tailnet>.ts.net:8766/mcp` and header `Authorization: Bearer <token>`.
3. Ask your main bot to **create a webhook routine** for Tether, and save its URL and key under `notify` in your config to enable replies back to your Macs.

## Usage

**From a cloud bot (Grok Bot):**

> Use tether to find why the login test is flaky in `my-app`. Read-only, and tell me what it finds.

> Have tether add input validation to the signup form in `my-app` (work mode) and wake me when it's done.

**From any local coding agent or terminal on your Macs:**

```bash
bot assistant "The deploy finished. Can you post the release notes?"
bot researcher "What's the status of the data import?" --wait 600   # waits for the reply
```

## MCP Tools

| Tool | What it does |
|---|---|
| `delegate_to_claude(repo, task, mode, notify?)` | Starts a headless job in an allowlisted repo. `mode` is `review` (read-only) or `work` (edits on a new branch). Returns a `job_id`. |
| `check_job(job_id)` | Returns job status, answer, branch, and diff stat. |
| `resume_claude(job_id, message)` | Continues a finished job with a follow-up in the same session and branch. |
| `list_jobs()` | Lists recent jobs. |
| `message_claude(message, reply_to?, from_bot?)` | Delivers a reply or message back to local agents (e.g. answering a `bot` call). |

## Configuration

`~/.config/claude-bridge/config.json` (see [config.example.json](config.example.json)):

| Key | Meaning |
|---|---|
| `owner` | Your name, used in delegated job instructions |
| `host`, `port` | Tailscale IP and port to listen on |
| `token_ref` | Bearer token the cloud bot sends |
| `claude_token_ref` | Token from `claude setup-token` for headless runs |
| `allowed_callers` | Allowed Tailscale device names (e.g. `grokbot-user-…`) |
| `repos` | Allowlisted repos: `url`, `branch_prefix`, `commit_trailer`, and `open_pr` for work branches |
| `notify`, `relay_via` | Bot webhook URLs/keys and which bot relays messages to the others |

Secrets can be referenced via `op://vault/item/field` (1Password CLI), `env:NAME`, or `file:/path`.

## Contributing

Issues and PRs are welcome. Run the test suite with:

```bash
python3 -m unittest discover -s tests
```

## License

[MIT](LICENSE). Community project, not affiliated with Anthropic or xAI.
