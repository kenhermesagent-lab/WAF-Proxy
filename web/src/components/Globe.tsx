import { useEffect, useMemo, useRef, useState } from "react";
import type { PointerEvent as ReactPointerEvent } from "react";
import type { GlobeHit, GlobePoint } from "../types";
import { LAND } from "../world";

const COLORS: Record<string, string> = {
  waf: "#ef4444",
  sqli: "#ef4444",
  xss: "#f97316",
  rce: "#ef4444",
  "php-injection": "#ef4444",
  "unix-shell": "#ef4444",
  lfi: "#f59e0b",
  protocol: "#ef4444",
  method: "#ef4444",
  scanner: "#a855f7",
  "country-block": "#8b5cf6",
  "asn-block": "#6366f1",
  asn: "#6366f1",
  dos: "#f59e0b",
  "temp-ban": "#a855f7",
  "permanent-ban": "#ec4899",
  feed: "#14b8a6",
  "bot-challenge": "#f97316",
  decoy: "#ec4899",
};

const GROUPS = [
  { id: "waf", label: "WAF block", color: "#ef4444" },
  { id: "dos", label: "DoS / rate", color: "#f59e0b" },
  { id: "ban", label: "ban / scanner", color: "#a855f7" },
  { id: "feed", label: "threat feed", color: "#14b8a6" },
] as const;

type GroupID = (typeof GROUPS)[number]["id"];

function groupFor(category: string): GroupID {
  switch (category) {
    case "dos":
      return "dos";
    case "temp-ban":
    case "permanent-ban":
    case "scanner":
    case "decoy":
    case "bot-challenge":
    case "country-block":
    case "asn-block":
    case "asn":
      return "ban";
    case "feed":
      return "feed";
    default:
      return "waf";
  }
}

function colorFor(category: string): string {
  return COLORS[category] ?? "#ef4444";
}

const DEG = Math.PI / 180;

// Severity ramp: a handful of hits is amber, a sustained burst burns red. The
// dot radius uses the same weight, so volume reads before the colour does.
const HEAT: [number, string][] = [
  [0, "#fbbf24"],
  [0.5, "#f97316"],
  [1, "#ef4444"],
];

function hexToRgb(hex: string): [number, number, number] {
  const n = parseInt(hex.slice(1), 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

function heatColor(weight: number): string {
  const x = Math.max(0, Math.min(1, weight));
  let lo = HEAT[0];
  let hi = HEAT[HEAT.length - 1];
  for (let i = 0; i < HEAT.length - 1; i++) {
    if (x >= HEAT[i][0] && x <= HEAT[i + 1][0]) {
      lo = HEAT[i];
      hi = HEAT[i + 1];
      break;
    }
  }
  const k = (x - lo[0]) / (hi[0] - lo[0] || 1);
  const a = hexToRgb(lo[1]);
  const b = hexToRgb(hi[1]);
  const c = a.map((v, i) => Math.round(v + (b[i] - v) * k));
  return `rgb(${c[0]},${c[1]},${c[2]})`;
}

type V3 = { x: number; y: number; z: number };

function unitVec(lat: number, lon: number): V3 {
  const phi = lat * DEG;
  const lambda = lon * DEG;
  return { x: Math.cos(phi) * Math.sin(lambda), y: Math.sin(phi), z: Math.cos(phi) * Math.cos(lambda) };
}

// Land and the graticule never change, so their unit vectors are built once at
// import time instead of running two trig calls per vertex per frame.
const LAND_V: V3[][] = LAND.map((ring) => ring.map(([lon, lat]) => unitVec(lat, lon)));

const GRID: V3[][] = (() => {
  const lines: V3[][] = [];
  for (const lat of [-60, -30, 0, 30, 60]) {
    const line: V3[] = [];
    for (let lon = 0; lon <= 360; lon += 6) line.push(unitVec(lat, lon));
    lines.push(line);
  }
  for (let lon = 0; lon < 360; lon += 30) {
    const line: V3[] = [];
    for (let lat = -88; lat <= 88; lat += 6) line.push(unitVec(lat, lon));
    lines.push(line);
  }
  return lines;
})();

type Screen = (v: V3, radius: number) => { x: number; y: number; z: number };

function makeProjector(rot: number, cx: number, cy: number): Screen {
  const a = rot * DEG;
  const ca = Math.cos(a);
  const sa = Math.sin(a);
  return (v, radius) => {
    const x = v.x * ca + v.z * sa;
    const z = v.z * ca - v.x * sa;
    return { x: cx + x * radius, y: cy - v.y * radius, z };
  };
}

// Great-circle samples in unrotated space, cached by the endpoint pair. The
// rotation is applied per frame, so the cache survives the whole animation.
const ARCS = new Map<string, V3[]>();
const ARC_LIFT = 0.22;

function arcFor(a: V3, b: V3): V3[] {
  const key = `${a.x.toFixed(3)},${a.y.toFixed(3)},${a.z.toFixed(3)}|${b.x.toFixed(3)},${b.y.toFixed(3)},${b.z.toFixed(3)}`;
  const hit = ARCS.get(key);
  if (hit) return hit;
  const dot = Math.max(-1, Math.min(1, a.x * b.x + a.y * b.y + a.z * b.z));
  const theta = Math.acos(dot);
  const steps = 40;
  const out: V3[] = [];
  if (theta < 1e-4) {
    for (let i = 0; i <= steps; i++) out.push(a);
  } else {
    const sin = Math.sin(theta);
    for (let i = 0; i <= steps; i++) {
      const t = i / steps;
      const k1 = Math.sin((1 - t) * theta) / sin;
      const k2 = Math.sin(t * theta) / sin;
      out.push({ x: a.x * k1 + b.x * k2, y: a.y * k1 + b.y * k2, z: a.z * k1 + b.z * k2 });
    }
  }
  if (ARCS.size > 800) ARCS.clear();
  ARCS.set(key, out);
  return out;
}

function arcPoint(samples: V3[], t: number, project: Screen, r: number) {
  const i = Math.min(samples.length - 1, Math.max(0, Math.round(t * (samples.length - 1))));
  const lift = 1 + ARC_LIFT * Math.sin(Math.PI * (i / (samples.length - 1)));
  return project(samples[i], r * lift);
}

function drawArc(
  ctx: CanvasRenderingContext2D,
  samples: V3[],
  project: Screen,
  r: number,
  color: string,
  alpha: number,
  width: number,
  blur: number,
) {
  ctx.save();
  ctx.globalCompositeOperation = "lighter";
  ctx.strokeStyle = color;
  ctx.globalAlpha = alpha;
  ctx.lineWidth = width;
  ctx.lineCap = "round";
  if (blur > 0) {
    ctx.shadowColor = color;
    ctx.shadowBlur = blur;
  }
  ctx.beginPath();
  let started = false;
  for (let i = 0; i < samples.length; i++) {
    const t = samples.length > 1 ? i / (samples.length - 1) : 0;
    const p = project(samples[i], r * (1 + ARC_LIFT * Math.sin(Math.PI * t)));
    if (p.z < -0.04) {
      started = false;
      continue;
    }
    if (started) ctx.lineTo(p.x, p.y);
    else {
      ctx.moveTo(p.x, p.y);
      started = true;
    }
  }
  ctx.stroke();
  ctx.restore();
}

type Column = { x: number; y: number; speed: number };
type Streak = { x: number; y: number; born: number; tokens: string[] };
type Live = { hit: GlobeHit; born: number; life: number };

const MATRIX_CHARS = "01SYNACKGETPOST403DENYWAFATKSCAN";
const KILL_TOKENS = ["BLOCK", "DROP", "BAN", "403", "DENY", "KILL"];

function seedMatrix(width: number): Column[] {
  const cols: Column[] = [];
  for (let x = 8; x < width; x += 13) {
    cols.push({ x, y: Math.random() * 240, speed: 18 + Math.random() * 42 });
  }
  return cols;
}

// Ambient rain is cold and faint; a blocked request drops a red streak through
// it, so the wall reads as "kill / quarantine" rather than decoration.
function drawMatrix(
  ctx: CanvasRenderingContext2D,
  columns: Column[],
  streaks: Streak[],
  width: number,
  height: number,
  now: number,
  dt: number,
  vignette: CanvasGradient | null,
) {
  ctx.font = "10px ui-monospace, SFMono-Regular, Menlo, monospace";
  ctx.textAlign = "center";
  for (const c of columns) {
    c.y += c.speed * dt;
    if (c.y > height + 20) {
      c.y = -Math.random() * 120;
      c.speed = 18 + Math.random() * 42;
    }
    const idx = ((Math.floor(c.y * 0.12 + c.x) % MATRIX_CHARS.length) + MATRIX_CHARS.length) % MATRIX_CHARS.length;
    const ch = MATRIX_CHARS[idx];
    ctx.fillStyle = "rgba(56,89,120,0.09)";
    ctx.fillText(ch, c.x, c.y);
    ctx.fillStyle = "rgba(125,170,210,0.13)";
    ctx.fillText(ch, c.x, c.y - 12);
  }
  for (const s of streaks) {
    const age = (now - s.born) / 1000;
    if (age > 1.1) continue;
    const fade = 1 - age / 1.1;
    ctx.font = "10px ui-monospace, SFMono-Regular, Menlo, monospace";
    for (let i = 0; i < s.tokens.length; i++) {
      const y = s.y + age * 120 - i * 11;
      if (y < -12 || y > height + 12) continue;
      ctx.fillStyle = `rgba(239,68,68,${(fade * (1 - i / s.tokens.length) * 0.85).toFixed(3)})`;
      ctx.fillText(s.tokens[i], s.x, y);
    }
  }
  if (vignette) {
    ctx.fillStyle = vignette;
    ctx.fillRect(0, 0, width, height);
  }
}

function drawLand(ctx: CanvasRenderingContext2D, project: Screen, cx: number, cy: number, r: number) {
  // Clip to the disc: coastlines that cross the horizon are folded onto the
  // limb, which keeps each shape closed and hides the far side.
  ctx.save();
  ctx.beginPath();
  ctx.arc(cx, cy, r, 0, Math.PI * 2);
  ctx.clip();
  ctx.fillStyle = "rgba(96,165,250,0.30)";
  ctx.strokeStyle = "rgba(191,219,254,0.60)";
  ctx.lineWidth = 0.9;
  for (const ring of LAND_V) {
    ctx.beginPath();
    let started = false;
    for (const v of ring) {
      const p = project(v, r);
      let x = p.x;
      let y = p.y;
      if (p.z <= 0) {
        const dx = p.x - cx;
        const dy = p.y - cy;
        const len = Math.hypot(dx, dy);
        if (len < 0.01) continue;
        x = cx + (dx / len) * r;
        y = cy + (dy / len) * r;
      }
      if (started) ctx.lineTo(x, y);
      else {
        ctx.moveTo(x, y);
        started = true;
      }
    }
    ctx.closePath();
    ctx.fill();
    ctx.stroke();
  }
  ctx.restore();
}

function flagEmoji(country: string): string {
  if (!/^[a-z]{2}$/i.test(country)) return "";
  const base = 0x1f1e6;
  return String.fromCodePoint(...[...country.toUpperCase()].map((c) => base + c.charCodeAt(0) - 65));
}

function ago(ts: string): string {
  const at = Date.parse(ts);
  if (!Number.isFinite(at)) return "—";
  const s = Math.max(0, Math.round((Date.now() - at) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  return `${Math.round(s / 3600)}h ago`;
}

type Tip = { x: number; y: number; pt: GlobePoint };

export default function Globe({
  points,
  hits,
  home,
  hours = 1,
}: {
  points: GlobePoint[];
  hits: GlobeHit[];
  home: { lat: number; lon: number };
  hours?: number;
}) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const size = useRef({ w: 0, h: 0 });
  const dots = useRef<{ x: number; y: number; r: number; pt: GlobePoint }[]>([]);
  const [visible, setVisible] = useState<Record<GroupID, boolean>>({ waf: true, dos: true, ban: true, feed: true });
  const [focus, setFocus] = useState<string | null>(null);
  const [tip, setTip] = useState<Tip | null>(null);
  // The animation loop never re-runs, so it reads hover state through a ref.
  const tipRef = useRef(false);
  tipRef.current = tip !== null;
  // One tick keeps "attacks / min" and "last hit" counting down between polls.
  const [tick, setTick] = useState(0);

  const state = useRef({ points, hits, home, visible, focus, rotation: 0 });
  state.current.points = points;
  state.current.hits = hits;
  state.current.home = home;
  state.current.visible = visible;
  state.current.focus = focus;

  useEffect(() => {
    const t = setInterval(() => setTick((n) => n + 1), 5000);
    return () => clearInterval(t);
  }, []);

  // The canvas follows its container instead of assuming a 0.56 aspect, so a
  // narrow card no longer crops the sphere and a resize is picked up at once.
  useEffect(() => {
    const wrap = wrapRef.current;
    if (!wrap) return;
    const measure = () => {
      size.current = { w: wrap.clientWidth, h: wrap.clientHeight };
    };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(wrap);
    return () => ro.disconnect();
  }, []);

  const counts = useMemo(() => {
    const out: Record<GroupID, number> = { waf: 0, dos: 0, ban: 0, feed: 0 };
    for (const p of points) out[groupFor(p.category)] += p.count;
    return out;
  }, [points]);

  const liveStats = useMemo(() => {
    const now = Date.now();
    const recent = hits.filter((h) => {
      const at = Date.parse(h.ts);
      return Number.isFinite(at) && now - at <= 60000;
    });
    const byCountry = new Map<string, number>();
    for (const h of recent) byCountry.set(h.country, (byCountry.get(h.country) ?? 0) + 1);
    const top = [...byCountry.entries()].sort((a, b) => b[1] - a[1])[0];
    const last = hits[0] ? Math.max(0, Math.round((now - Date.parse(hits[0].ts)) / 1000)) : null;
    return { perMin: recent.length, top, last };
    // tick is intentional: it re-reads the clock so the window slides.
  }, [hits, tick]);

  const summary = useMemo(() => {
    const parts = GROUPS.map((g) => `${counts[g.id].toLocaleString()} ${g.label}`).join(", ");
    return `Attack globe over the last ${hours} hour${hours === 1 ? "" : "s"}: ${parts}.`;
  }, [counts, hours]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let raf = 0;
    let last = performance.now();
    let columns: Column[] = [];
    let columnWidth = 0;
    let live: Live[] = [];
    let streaks: Streak[] = [];
    const seen = new Set<number>();
    let primed = false;
    const follow = { target: 0, until: 0, active: false };
    const cache: {
      key: string;
      sphere: CanvasGradient | null;
      shade: CanvasGradient | null;
      glow: CanvasGradient | null;
      vignette: CanvasGradient | null;
    } = { key: "", sphere: null, shade: null, glow: null, vignette: null };

    const draw = (now: number) => {
      const dt = Math.min(0.05, (now - last) / 1000);
      last = now;
      const reduced = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
      const paused = reduced || document.visibilityState !== "visible";

      if (!paused) {
        // A new burst eases the sphere round to face the source, then hands
        // control back to the slow spin so the map keeps showing everything.
        if (follow.active && now < follow.until) {
          let delta = follow.target - state.current.rotation;
          delta = (((delta + 180) % 360) + 360) % 360 - 180;
          state.current.rotation += delta * Math.min(1, dt * 2.4);
        } else {
          follow.active = false;
          state.current.rotation = (state.current.rotation + dt * 4) % 360;
        }
      }

      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const cssW = Math.round(size.current.w || canvas.clientWidth || 640);
      const cssH = Math.round(size.current.h || cssW * 0.5625);
      if (canvas.width !== Math.round(cssW * dpr) || canvas.height !== Math.round(cssH * dpr)) {
        canvas.width = Math.round(cssW * dpr);
        canvas.height = Math.round(cssH * dpr);
        columns = [];
      }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, cssW, cssH);

      const cx = cssW / 2;
      const cy = cssH / 2;
      const r = Math.min(cssW, cssH) * 0.4;
      const rot = state.current.rotation;
      const project = makeProjector(rot, cx, cy);

      if (cache.key !== `${cssW}x${cssH}`) {
        cache.key = `${cssW}x${cssH}`;
        const sphere = ctx.createRadialGradient(cx - r * 0.34, cy - r * 0.36, r * 0.08, cx, cy, r * 1.05);
        sphere.addColorStop(0, "#1b2a44");
        sphere.addColorStop(0.55, "#101a28");
        sphere.addColorStop(1, "#06090e");
        cache.sphere = sphere;
        const shade = ctx.createRadialGradient(cx - r * 0.3, cy - r * 0.32, r * 0.1, cx, cy, r * 1.02);
        shade.addColorStop(0, "rgba(0,0,0,0)");
        shade.addColorStop(0.62, "rgba(0,0,0,0.12)");
        shade.addColorStop(1, "rgba(0,0,0,0.52)");
        cache.shade = shade;
        const glow = ctx.createRadialGradient(cx, cy, r * 0.96, cx, cy, r * 1.3);
        glow.addColorStop(0, "rgba(56,132,255,0.30)");
        glow.addColorStop(0.45, "rgba(37,99,235,0.12)");
        glow.addColorStop(1, "rgba(11,13,16,0)");
        cache.glow = glow;
        const v = ctx.createLinearGradient(0, 0, 0, cssH);
        v.addColorStop(0, "rgba(11,13,16,0.06)");
        v.addColorStop(1, "rgba(11,13,16,0.22)");
        cache.vignette = v;
      }

      if (columns.length === 0 || Math.abs(columnWidth - cssW) > 1) {
        columnWidth = cssW;
        columns = seedMatrix(cssW);
      }
      if (!paused) {
        streaks = streaks.filter((s) => now - s.born < 1100);
        drawMatrix(ctx, columns, streaks, cssW, cssH, now, dt, cache.vignette);
      } else if (cache.vignette) {
        ctx.fillStyle = cache.vignette;
        ctx.fillRect(0, 0, cssW, cssH);
      }

      // atmosphere
      if (cache.glow) {
        ctx.save();
        ctx.globalCompositeOperation = "lighter";
        ctx.fillStyle = cache.glow;
        ctx.fillRect(0, 0, cssW, cssH);
        ctx.restore();
      }

      // lit sphere body
      if (cache.sphere) {
        ctx.beginPath();
        ctx.arc(cx, cy, r, 0, Math.PI * 2);
        ctx.fillStyle = cache.sphere;
        ctx.fill();
      }

      // graticule
      ctx.strokeStyle = "rgba(96,165,250,0.11)";
      ctx.lineWidth = 1;
      for (const line of GRID) {
        ctx.beginPath();
        let started = false;
        for (const v of line) {
          const p = project(v, r);
          if (p.z <= 0) {
            started = false;
            continue;
          }
          if (started) ctx.lineTo(p.x, p.y);
          else {
            ctx.moveTo(p.x, p.y);
            started = true;
          }
        }
        ctx.stroke();
      }

      drawLand(ctx, project, cx, cy, r);

      // limb darkening over the land, so the sphere reads as a ball rather
      // than a flat map.
      if (cache.shade) {
        ctx.save();
        ctx.beginPath();
        ctx.arc(cx, cy, r, 0, Math.PI * 2);
        ctx.clip();
        ctx.fillStyle = cache.shade;
        ctx.fillRect(cx - r, cy - r, r * 2, r * 2);
        ctx.restore();
      }

      // ---- hits: spawn an arc + a kill streak for anything new ----
      const hitList = state.current.hits;
      const homeVec = unitVec(state.current.home.lat, state.current.home.lon);
      if (!primed) {
        // The first payload is the last minute of history. Only the newest few
        // seconds animate, so opening the dashboard does not fire sixty arcs.
        for (const h of hitList) seen.add(h.id);
        const wall = Date.now();
        for (let i = hitList.length - 1; i >= 0; i--) {
          const h = hitList[i];
          const at = Date.parse(h.ts);
          if (Number.isFinite(at) && wall - at < 8000) live.push({ hit: h, born: now, life: 1200 });
        }
        primed = true;
      } else {
        for (let i = hitList.length - 1; i >= 0; i--) {
          const h = hitList[i];
          if (seen.has(h.id)) continue;
          seen.add(h.id);
          live.push({ hit: h, born: now, life: 1200 });
          const p = project(unitVec(h.lat, h.lon), r);
          if (p.z > -0.05 && p.x > 4 && p.x < cssW - 4) {
            const tokens: string[] = [];
            for (let k = 0; k < 4; k++) tokens.push(KILL_TOKENS[Math.floor(Math.random() * KILL_TOKENS.length)]);
            streaks.push({ x: p.x, y: Math.max(0, p.y), born: now, tokens });
            if (streaks.length > 18) streaks.splice(0, streaks.length - 18);
          }
          if (!reduced && !tipRef.current && now - follow.until > 4000) {
            const facing = project(unitVec(h.lat, h.lon), r);
            if (facing.z < 0.25) {
              follow.target = -h.lon;
              follow.until = now + 2600;
              follow.active = true;
            }
          }
        }
        if (seen.size > 600) {
          seen.clear();
          for (const h of hitList) seen.add(h.id);
        }
      }
      live = live.filter((l) => now - l.born < l.life);

      const homeP = project(homeVec, r);
      const focus = state.current.focus;
      const shown = state.current.points.filter((p) => state.current.visible[groupFor(p.category)]);
      // Aggregated arcs are drawn brightest for the busiest sources; the rest
      // stay as faint strands so nothing is silently dropped.
      const hot = shown.slice(0, 40);
      const now2 = now / 1000;

      for (let i = 0; i < shown.length; i++) {
        const pt = shown[i];
        const dim = focus && pt.country !== focus;
        const target = project(unitVec(pt.lat, pt.lon), r);
        if (target.z <= 0 || homeP.z <= 0) continue;
        const weight = Math.min(1, Math.log10(1 + pt.count) / 3);
        const samples = arcFor(unitVec(pt.lat, pt.lon), homeVec);
        const isHot = i < hot.length && !dim;
        drawArc(
          ctx,
          samples,
          project,
          r,
          colorFor(pt.category),
          dim ? 0.05 : 0.22 + weight * 0.5,
          isHot ? 1.45 : 0.8,
          isHot ? 7 : 0,
        );
        if (isHot && !paused) {
          const t = (now2 * 0.22 + i * 0.13) % 1;
          const p = arcPoint(samples, t, project, r);
          if (p.z > 0) {
            ctx.save();
            ctx.globalCompositeOperation = "lighter";
            ctx.fillStyle = "#dbeafe";
            ctx.globalAlpha = 0.85;
            ctx.beginPath();
            ctx.arc(p.x, p.y, 1.5, 0, Math.PI * 2);
            ctx.fill();
            ctx.restore();
          }
        }
      }

      // ---- live hits: a comet crosses in 1.2s ----
      for (const l of live) {
        const t = Math.min(1, (now - l.born) / l.life);
        const fade = 1 - t;
        const a = unitVec(l.hit.lat, l.hit.lon);
        const samples = arcFor(a, homeVec);
        const color = colorFor(l.hit.category);
        drawArc(ctx, samples, project, r, color, 0.22 + fade * 0.75, 1.8, 9);
        const p = arcPoint(samples, t, project, r);
        if (p.z > 0) {
          ctx.save();
          ctx.globalCompositeOperation = "lighter";
          ctx.shadowColor = color;
          ctx.shadowBlur = 12;
          ctx.fillStyle = "#ffffff";
          ctx.globalAlpha = 0.35 + fade * 0.65;
          ctx.beginPath();
          ctx.arc(p.x, p.y, 2.6, 0, Math.PI * 2);
          ctx.fill();
          ctx.restore();
        }
      }

      // ---- dots: heat colour, volume-sized radius ----
      const next: { x: number; y: number; r: number; pt: GlobePoint }[] = [];
      for (const pt of shown) {
        const target = project(unitVec(pt.lat, pt.lon), r);
        if (target.z <= 0) continue;
        const dim = focus && pt.country !== focus;
        const weight = Math.min(1, Math.log10(1 + pt.count) / 3);
        const radius = 3 + weight * 11;
        const group = groupFor(pt.category);
        ctx.save();
        if (!dim) {
          // A flat wash instead of a per-dot gradient: hundreds of gradients a
          // frame is the one thing that used to drop this canvas off 60fps.
          ctx.globalAlpha = 0.14;
          ctx.fillStyle = colorFor(pt.category);
          ctx.beginPath();
          ctx.arc(target.x, target.y, radius * 2.1, 0, Math.PI * 2);
          ctx.fill();
        }
        ctx.globalAlpha = dim ? 0.18 : 0.92;
        ctx.fillStyle = heatColor(weight);
        ctx.beginPath();
        ctx.arc(target.x, target.y, radius, 0, Math.PI * 2);
        ctx.fill();
        ctx.globalAlpha = dim ? 0.25 : 0.9;
        ctx.strokeStyle = GROUPS.find((g) => g.id === group)?.color ?? "#ef4444";
        ctx.lineWidth = 1.1;
        ctx.beginPath();
        ctx.arc(target.x, target.y, radius + 2.2, 0, Math.PI * 2);
        ctx.stroke();
        ctx.restore();
        if (!dim) next.push({ x: target.x, y: target.y, r: radius, pt });
      }
      dots.current = next;

      if (homeP.z > 0) {
        ctx.save();
        ctx.globalCompositeOperation = "lighter";
        ctx.fillStyle = "#bfdbfe";
        ctx.beginPath();
        ctx.arc(homeP.x, homeP.y, 3.2, 0, Math.PI * 2);
        ctx.fill();
        ctx.strokeStyle = "rgba(191,219,254,0.55)";
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.arc(homeP.x, homeP.y, 7 + Math.sin(now2 * 2) * 1.6, 0, Math.PI * 2);
        ctx.stroke();
        ctx.restore();
      }

      ctx.strokeStyle = "rgba(96,165,250,0.34)";
      ctx.lineWidth = 1.2;
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.stroke();

      raf = requestAnimationFrame(draw);
    };
    raf = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(raf);
    // tip is read through the closure only to pause the camera while hovering.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const onMove = (e: ReactPointerEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    let best: Tip | null = null;
    let bestDist = Infinity;
    for (const d of dots.current) {
      const dist = Math.hypot(d.x - x, d.y - y);
      if (dist <= d.r + 7 && dist < bestDist) {
        bestDist = dist;
        best = { x, y, pt: d.pt };
      }
    }
    setTip((prev) => {
      if (!best) return prev === null ? prev : null;
      if (
        prev &&
        prev.pt.country === best.pt.country &&
        prev.pt.host === best.pt.host &&
        prev.pt.category === best.pt.category &&
        Math.abs(prev.x - x) < 2 &&
        Math.abs(prev.y - y) < 2
      ) {
        return prev;
      }
      return best;
    });
  };

  const pin = () => {
    if (!tip || !tip.pt.country) return;
    setFocus((f) => (f === tip.pt.country ? null : tip.pt.country));
  };

  const tipW = 210;
  const tipLeft = tip ? Math.min(tip.x + 14, Math.max(6, (size.current.w || 0) - tipW - 6)) : 0;

  return (
    <div className="globe-wrap" ref={wrapRef}>
      <canvas
        ref={canvasRef}
        role="img"
        aria-label="World map of recent blocked attacks"
        onPointerMove={onMove}
        onPointerLeave={() => setTip(null)}
        onClick={pin}
        style={{ cursor: tip ? "pointer" : "default" }}
      />
      <div className="globe-hud" aria-hidden="true">
        <span className="globe-hud-rate">
          <b>{liveStats.perMin}</b> attacks/min
        </span>
        <span>
          last {hours}h · <b>{shownTotal(counts).toLocaleString()}</b> blocked
        </span>
        {liveStats.top && (
          <span>
            top {flagEmoji(liveStats.top[0])} {liveStats.top[0]} · {liveStats.top[1]}
          </span>
        )}
        {liveStats.last !== null && <span className="globe-hud-last">last hit {liveStats.last}s ago</span>}
        {focus && (
          <button className="globe-focus" onClick={() => setFocus(null)} title="Clear the country filter">
            {flagEmoji(focus)} {focus} ✕
          </button>
        )}
      </div>
      <p className="sr-only" aria-live="polite">
        {summary}
      </p>
      {tip && (
        <div className="globe-tip" style={{ left: tipLeft, top: Math.max(6, tip.y - 12), width: tipW }}>
          <div className="globe-tip-head">
            <span>
              {flagEmoji(tip.pt.country)} {tip.pt.country || "unknown"}
            </span>
            <b>{tip.pt.count.toLocaleString()}</b>
          </div>
          <div className="globe-tip-row">{tip.pt.host || "any host"}</div>
          <div className="globe-tip-row">
            {tip.pt.category} · {ago(tip.pt.last_seen)}
          </div>
          <div className="globe-tip-hint">click to isolate</div>
        </div>
      )}
      <div className="globe-legend" aria-label="Attack categories">
        {GROUPS.map((g) => (
          <button
            key={g.id}
            className={`globe-key ${visible[g.id] ? "" : "off"}`}
            onClick={() => setVisible((v) => ({ ...v, [g.id]: !v[g.id] }))}
            aria-pressed={visible[g.id]}
            title={`${visible[g.id] ? "Hide" : "Show"} ${g.label}`}
          >
            <i style={{ background: g.color }} />
            {g.label}
            <b>{counts[g.id].toLocaleString()}</b>
          </button>
        ))}
      </div>
    </div>
  );
}

function shownTotal(counts: Record<GroupID, number>): number {
  return GROUPS.reduce((n, g) => n + counts[g.id], 0);
}
