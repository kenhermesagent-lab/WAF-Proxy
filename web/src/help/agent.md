## What this page is for
Machine access to the console: the MCP endpoint and the tokens that let an agent read or act.

## Concepts
- **Token** — a named credential with a scope; revoke it when the agent is retired.
- **MCP endpoint** — `/mcp`, over the same address as the console.
- **Audit trail** — every tool call is written as `mcp:<token name>`, next to administrator changes.

## First tasks
- Create one token per agent, never a shared one.
- Revoke and reissue rather than editing a token's scope.
