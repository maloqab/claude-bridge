# Security

claude-bridge runs Claude Code on your machine on behalf of remote bots, so please report security problems
privately: use **GitHub → Security → Report a vulnerability** on this repo. Please don't open a public issue.
Include what an attacker needs (network position, the token, a bot account, a PR author, …) and the impact.

How the bridge is meant to be safe:
- It listens only on your Tailscale IP. Each request needs the bearer token and an allowed tailnet device.
- Claude jobs get a fixed toolset (no shell, no web), can't read or write outside the job's git worktree, and
  load no user or project settings, hooks or MCP servers. The bridge does the git work itself.
- PR reviews treat the PR as untrusted: they skip forks and remove the PR's agent config files before Claude
  reads it.

See "Security notes" in [docs/SETUP.md](docs/SETUP.md) for how to run it safely.
