import type { IntelAbuse, IntelPlan, IntelQuota } from "./types";

// The plan comes from the key's rate-limit ceiling. The API never names it, so
// the card says which tier the ceiling belongs to and how many checks it carries.
export function describePlan(plan: IntelPlan | undefined, quota: IntelQuota | undefined): string {
  if (plan) {
    return `${plan.name} · ${plan.checks_per_day.toLocaleString()} checks/day`;
  }
  if (quota && quota.limit > 0) {
    return `allowance ${quota.limit.toLocaleString()}/day · plan not recognised`;
  }
  // Nothing has reported headers yet: a probe that failed never will, so the
  // card must not claim a check is still running.
  return "allowance not reported yet";
}

export type QuotaView = {
  limit: number;
  remaining: number;
  used: number;
  percent: number;
  reset: string;
};

// percent is used quota, clamped so a rounding surprise cannot draw a bar past
// its track.
export function quotaView(quota: IntelQuota | undefined): QuotaView | null {
  if (!quota || quota.limit <= 0) return null;
  const remaining = Math.max(0, Math.min(quota.limit, quota.remaining));
  const used = quota.limit - remaining;
  return {
    limit: quota.limit,
    remaining,
    used,
    percent: Math.round((used / quota.limit) * 1000) / 10,
    reset: quota.reset_at ? quota.reset_at.slice(11, 16) + " UTC" : "unknown",
  };
}

// quotaTone colours the allowance bar by how much of it is spent: a gradient
// squeezed into the filled width made an almost untouched allowance look red.
export function quotaTone(percent: number): string {
  if (percent >= 90) return "#ef4444";
  if (percent >= 70) return "#f59e0b";
  return "#14b8a6";
}

// abuseTone follows the score thresholds AbuseIPDB documents: under 25 is
// rarely reported, over 75 is close to certain.
export function abuseTone(score: number): "ok" | "warn" | "bad" | "" {
  if (score >= 75) return "bad";
  if (score >= 25) return "warn";
  return "ok";
}

export function abuseSummary(abuse: IntelAbuse | undefined): string {
  if (!abuse) return "No key saved; add one in Settings";
  if (abuse.error) return abuse.error;
  const parts = [`${abuse.reports.toLocaleString()} reports`];
  if (abuse.reporters > 0) parts.push(`${abuse.reporters.toLocaleString()} reporters`);
  if (abuse.last_reported) parts.push(`last ${abuse.last_reported.slice(0, 10)}`);
  return parts.join(" · ");
}
