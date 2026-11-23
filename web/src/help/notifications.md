## What this page is for
Where alerts go: Telegram, email and a webhook, each switched per event.

## Concepts
- **Channel** — one delivery method; enable it once and every event reaches it unless you untick it.
- **Event** — a class of alert, such as a new ban or a failed update.
- **Test** — sends one message through the channel so you know it works before an incident.

## First tasks
- Enable one channel and use Test; a channel nobody verified is a channel that fails silently.
- Untick the events you do not want, rather than disabling the whole channel.
