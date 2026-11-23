/// <reference types="vite/client" />
// Page help is compiled into the bundle: a self-hosted console is often on a
// LAN with no internet, so a hosted docs link would be dead exactly when a new
// administrator needs it.
const files = import.meta.glob("./*.md", { query: "?raw", import: "default", eager: true }) as Record<string, string>;

export const HELP: Record<string, string> = Object.fromEntries(
  Object.entries(files).map(([path, text]) => [path.replace(/^\.\//, "").replace(/\.md$/, ""), text]),
);

export function helpFor(page: string): string | undefined {
  return HELP[page];
}

// hrefHelp is the printable copy of a page's help: the same Markdown and
// renderer, on a route of its own that carries no console chrome.
export function hrefHelp(page: string): string {
  return `#/${page}/help`;
}

// helpPageFromHash returns the page whose printable help the hash asks for,
// or null for every other route. It only answers for pages that have help, so
// a mistyped hash still falls through to the normal router.
export function helpPageFromHash(hash: string): string | null {
  const path = hash.split("?")[0].replace(/^#\/?/, "");
  const [page = "", view = "", extra] = path.split("/").filter(Boolean);
  if (extra !== undefined || view !== "help") return null;
  return HELP[page] ? page : null;
}
