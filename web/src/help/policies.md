## What this page is for
The rules that decide what is allowed: bans, WAF profiles, access profiles, block lists and the bot filter.

## Concepts
- **Ban** — a time-limited block for one address or range.
- **WAF profile** — the request checks applied to a site: rules, thresholds and what happens when one matches.
- **Access profile** — who may reach a site at all, including the sign-in gate and its accounts.
- **Mode** — `detect` logs a match without blocking; `block` refuses it. Start in detect when you are unsure.

## First tasks
- Read the default profile before writing a new one, then change one rule at a time.
- Put a new rule in detect mode for a day and read Logs before switching it to block.
