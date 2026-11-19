# claude-bridge

**Connect your Grok Bots to Claude Code, both ways.**

claude-bridge is a small MCP server that runs on your own Mac. Your Grok Bots connect to it over Tailscale and
can give Claude Code work in your repositories. Claude Code can message any of your bots and get answers back.

```
Grok Bot  ──  delegate_to_claude  ──▶  claude-bridge  ──▶  Claude Code
   ▲                                       │
   └──── webhook (job done, or a message from Claude) ◀────┘
```

## Features

- **Grok → Claude.** A bot calls `delegate_to_claude` to start a Claude Code job in one of your repos, either
  read-only or with edits on a fresh branch, then reads the result with `check_job`.
- **Claude → Grok.** From any Claude Code session, `bot elon "…"` wakes a bot, and the bot answers with
  `message_claude`. Bots without their own webhook are reached through your main bot.
- **Conversations.** `resume_claude` continues a finished job with a follow-up, in the same session and branch.
- **Private by default.** It runs on your Mac and is reachable only on your tailnet. Nothing is exposed to the internet.
- **Small.** It's one Python file with no dependencies.

## Requirements

- A Mac that stays on, with Python 3.9+, git and [Claude Code](https://claude.com/claude-code)
- [Tailscale](https://tailscale.com) on that Mac
- [Grok Bot](https://grok.com) with its Tailscale plugin connected

## Quick start

> **Easiest:** give [docs/SETUP.md](docs/SETUP.md) to your coding agent. It does the Mac side and tells you the
> few clicks to make in Grok Bot.

```bash
git clone https://github.com/maloqab/claude-bridge ~/claude-bridge
cd ~/claude-bridge && sh deploy/install.sh        # installs the service and creates the config
claude setup-token                                # a token for Claude Code to run headless
```

1. Fill in `~/.config/claude-bridge/config.json`. You need your Tailscale IP, a bearer token, your Claude token
   and the repos to allow; see [Configuration](#configuration).
2. In Grok Bot: **Connect apps → Add a custom connector → Remote HTTPS**. Use the URL
   `http://<your-mac>.<tailnet>.ts.net:8766/mcp` and the header `Authorization: Bearer <token>`.
3. Ask your bot to **create a webhook routine** for claude-bridge, and put its URL and key under `notify` in the
   config. That gives you the way back.

## Usage

**In Grok Bot**, just ask:

> Use claude-bridge to have Claude find why the login test is flaky in `my-app`. Read-only, and tell me what it finds.

> Have Claude add input validation to the signup form in `my-app` (work mode) and wake me when it's done.

**From Claude Code** (or any terminal on your Macs):

```bash
bot elon "The deploy finished. Can you post the release notes?"
bot jaber "What's the status of the data import?" --wait 600   # waits for the reply
```

## Tools

| Tool | What it does |
|---|---|
| `delegate_to_claude(repo, task, mode, notify?)` | Starts a Claude Code job. `mode` is `review` (read-only) or `work` (edits on a new branch). Returns a `job_id`. |
| `check_job(job_id)` | Gets the status, Claude's answer, the branch and the diff stat. |
| `resume_claude(job_id, message)` | Continues a finished job with a follow-up. |
| `list_jobs()` | Lists recent jobs. |
| `message_claude(message, reply_to?, from_bot?)` | Sends Claude Code a message, e.g. an answer to `bot`. |

## Configuration

`~/.config/claude-bridge/config.json` (see [config.example.json](config.example.json)):

| Key | Meaning |
|---|---|
| `owner` | Your name, used in Claude's instructions |
| `host`, `port` | The Tailscale IP and port to listen on |
| `token_ref` | The bearer token Grok sends |
| `claude_token_ref` | Your `claude setup-token` token |
| `allowed_callers` | Tailscale device names allowed to call (Grok's is `grokbot-user-…`) |
| `repos` | Repos bots may use: `url`, `branch_prefix`, `commit_trailer`, and `open_pr` to push work branches |
| `notify`, `relay_via` | Bots' webhook URL and key, and which bot relays to the others |

Secrets can be `op://vault/item/field` (1Password CLI), `env:NAME` or `file:/path`.

## Contributing

Issues and PRs are welcome. Run the tests with `python3 -m unittest discover -s tests`.

## License

[MIT](LICENSE). This is a community project, not affiliated with Anthropic or xAI.
