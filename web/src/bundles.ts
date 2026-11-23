export type BundleModes = Record<string, string>;
export type ModeCounts = Record<string, number>;

export type ModeBadge = { tone: "" | "ok" | "warn" | "bad"; label: string };

// An unset bundle logs only, which is what the server assumes too.
export function bundleMode(modes: BundleModes | undefined, name: string): string {
  const mode = modes?.[name];
  return mode === "off" || mode === "block" || mode === "log" ? mode : "log";
}

// modeBadges turns a per-profile count into the badges the tables show.
export function modeBadges(modes: ModeCounts | undefined): ModeBadge[] {
  const out: ModeBadge[] = [];
  const block = modes?.block ?? 0;
  const log = modes?.log ?? 0;
  const off = modes?.off ?? 0;
  if (block > 0) out.push({ tone: "bad", label: `${block} block` });
  if (log > 0) out.push({ tone: "warn", label: `${log} log only` });
  if (off > 0) out.push({ tone: "", label: `${off} off` });
  return out;
}

// profileBundleBadges summarises a profile against the installed packs.
export function profileBundleBadges(profile: { bundle_modes?: BundleModes }, names: string[]): ModeBadge[] {
  const counts: ModeCounts = { block: 0, log: 0, off: 0 };
  for (const name of names) {
    counts[bundleMode(profile.bundle_modes, name)]++;
  }
  return modeBadges(counts);
}

// outcomeBadges says what the requests that matched a rule actually got. It is
// per hit, so a bundle two sites run differently still reads correctly.
export function outcomeBadges(hit: { blocked: number; logged: number }): ModeBadge[] {
  const out: ModeBadge[] = [];
  if (hit.blocked > 0) out.push({ tone: "bad", label: `${hit.blocked.toLocaleString()} blocked` });
  if (hit.logged > 0) out.push({ tone: "warn", label: `${hit.logged.toLocaleString()} logged` });
  if (out.length === 0) out.push({ tone: "", label: "off" });
  return out;
}

// loggedOnly is true when every match was served: no profile blocks these
// rules yet. An empty list is not "logged only"; the card shows its empty state.
export function loggedOnly(hits: { blocked: number; logged: number }[]): boolean {
  return hits.length > 0 && hits.every((h) => h.blocked === 0);
}

// hitsByBundle groups the hit table by pack for the profile dialog.
export function hitsByBundle(rules: { bundle?: string; hits: number }[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const r of rules) {
    if (!r.bundle) continue;
    out[r.bundle] = (out[r.bundle] ?? 0) + r.hits;
  }
  return out;
}
