## What this page is for
The request log: one row per request the proxy handled, with the WAF's verdict and why.

## Concepts
- **Outcome** — allowed, blocked or challenged. A blocked row names the rule that matched.
- **Filters** — hostname, address, path and outcome, combinable. The URL keeps them, so a filtered view can be shared.
- **Export** — CSV for the current filters, for a spreadsheet or an incident report.

## First tasks
- Filter to one hostname and add `outcome=blocked` to see only refusals.
- Save a filter you use often as a view; it appears in the Logs toolbar.

## If it stays empty
Traffic appears here once a request reaches a proxied hostname. Check that a hostname exists and that DNS points at this box.
