import { forwardRef, useEffect, useImperativeHandle, useMemo, useRef, useState } from "react";
import type { MouseEvent as ReactMouseEvent, PointerEvent as ReactPointerEvent } from "react";
import type { GlobeHit, GlobePoint } from "../types";
import { countryName } from "../countries";
import { COUNTRY_LABELS, COUNTRY_SHAPES } from "../countries-geo";
import Icon from "./Icon";

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
  "list-block": "#8b5cf6",
  "list-allow": "#8b5cf6",
  "asn-block": "#6366f1",
  asn: "#6366f1",
  dos: "#f59e0b",
  "temp-ban": "#a855f7",
  "permanent-ban": "#ec4899",
  feed: "#14b8a6",
  "bot-challenge": "#60a5fa",
  "bot-filter": "#60a5fa",
  decoy: "#ec4899",
};

const GROUPS = [
  { id: "waf", label: "WAF block", color: "#ef4444" },
  { id: "dos", label: "DoS / rate", color: "#f59e0b" },
  { id: "bot", label: "Bot protection", color: "#60a5fa" },
  { id: "ban", label: "Ban / scanner", color: "#a855f7" },
  { id: "feed", label: "Threat feed", color: "#14b8a6" },
] as const;

type GroupID = (typeof GROUPS)[number]["id"];

function groupFor(category: string): GroupID {
  switch (category) {
    case "dos":
    case "login-limit":
    case "rate-limit":
      return "dos";
    case "bot-filter":
    case "bot-challenge":
      return "bot";
    case "temp-ban":
    case "permanent-ban":
    case "scanner":
    case "decoy":
    case "country-block":
    case "list-block":
    case "list-allow":
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

// Country rings and the graticule never change, so their unit vectors are built
// once at import time instead of running two trig calls per vertex per frame.
type Country = { code: string; rings: V3[][]; label: V3 };
const COUNTRIES_V: Country[] = Object.entries(COUNTRY_SHAPES).map(([code, rings]) => {
  const label = COUNTRY_LABELS[code] || rings[0][0];
  return {
    code,
    rings: rings.map((ring) => ring.map(([lon, lat]) => unitVec(lat, lon))),
    label: unitVec(label[1], label[0]),
  };
});

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

// The camera turns around the poles first (yaw) and then tilts (pitch), so a
// click can put any city in the middle of the sphere instead of only bringing
// its meridian to the front.
function makeProjector(yaw: number, pitch: number, cx: number, cy: number): Screen {
  const a = yaw * DEG;
  const ca = Math.cos(a);
  const sa = Math.sin(a);
  const b = pitch * DEG;
  const cb = Math.cos(b);
  const sb = Math.sin(b);
  return (v, radius) => {
    const x = v.x * ca + v.z * sa;
    const z = v.z * ca - v.x * sa;
    const y = v.y * cb - z * sb;
    const zz = z * cb + v.y * sb;
    return { x: cx + x * radius, y: cy - y * radius, z: zz };
  };
}

const ZOOM_MIN = 1;
const ZOOM_MAX = 4.5;
const PITCH_LIMIT = 1.15;
const HOME_PITCH = 0.05;

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

type Live = { hit: GlobeHit; born: number; life: number };

function countryPath(ctx: CanvasRenderingContext2D | Path2D, country: Country, project: Screen, cx: number, cy: number, r: number) {
  for (const ring of country.rings) {
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
    if (started) ctx.closePath();
  }
}

function drawCountries(
  ctx: CanvasRenderingContext2D,
  project: Screen,
  cx: number,
  cy: number,
  r: number,
  counts: Map<string, number>,
  max: number,
  focus: string | null,
) {
  // Clip to the disc: coasts that cross the horizon are folded onto the limb,
  // which keeps each shape closed and hides the far side.
  ctx.save();
  ctx.beginPath();
  ctx.arc(cx, cy, r, 0, Math.PI * 2);
  ctx.clip();
  for (const country of COUNTRIES_V) {
    if (project(country.label, r).z <= 0.01) continue;
    const count = counts.get(country.code) ?? 0;
    const dim = focus !== null && country.code !== focus;
    const selected = focus === country.code;
    const weight = count > 0 ? Math.min(1, Math.log10(1 + count) / Math.log10(1 + max)) : 0;
    ctx.globalAlpha = dim ? 0.35 : 1;
    ctx.beginPath();
    countryPath(ctx, country, project, cx, cy, r);
    ctx.fillStyle = count > 0 ? heatColor(weight) : "rgba(96,165,250,0.13)";
    ctx.fill();
    ctx.strokeStyle = selected
      ? "rgba(235,245,255,0.9)"
      : count > 0
        ? "rgba(255,190,164,0.5)"
        : "rgba(191,219,254,0.24)";
    ctx.lineWidth = selected ? 1.4 : count > 0 ? 0.8 : 0.55;
    ctx.stroke();
  }
  ctx.restore();
}

function drawCountryLabels(
  ctx: CanvasRenderingContext2D,
  project: Screen,
  r: number,
  w: number,
  h: number,
  counts: Map<string, number>,
  focus: string | null,
) {
  const top = [...counts.entries()]
    .filter(([code]) => COUNTRY_LABELS[code])
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6);
  if (focus && !top.some(([code]) => code === focus)) {
    const count = counts.get(focus);
    if (count) top.unshift([focus, count]);
  }
  // Keep the top-left HUD clear.
  const taken: { x: number; y: number; w: number; h: number }[] = [
    { x: 6, y: 6, w: 220, h: 54 },
  ];
  ctx.save();
  ctx.font = "500 10px Inter, ui-sans-serif, sans-serif";
  ctx.textBaseline = "middle";
  for (const [code, count] of top) {
    const at = COUNTRY_LABELS[code];
    if (!at) continue;
    const p = project(unitVec(at[1], at[0]), r);
    if (p.z <= 0.08) continue;
    ctx.globalAlpha = focus && focus !== code ? 0.4 : 1;
    const text = `${flagEmoji(code)} ${countryName(code)}  ${count.toLocaleString()}`;
    const width = Math.ceil(ctx.measureText(text).width) + 14;
    const height = 20;
    const box = {
      x: Math.max(8, Math.min(w - width - 8, p.x - width / 2)),
      y: Math.max(8, Math.min(h - height - 8, p.y - height / 2)),
      w: width,
      h: height,
    };
    if (taken.some((b) => box.x < b.x + b.w + 4 && box.x + box.w + 4 > b.x && box.y < b.y + b.h + 3 && box.y + box.h + 3 > b.y)) continue;
    taken.push(box);
    ctx.beginPath();
    ctx.roundRect(box.x, box.y, box.w, box.h, 5);
    ctx.fillStyle = "rgba(7,15,23,0.9)";
    ctx.fill();
    ctx.strokeStyle = focus === code ? "rgba(157,192,255,0.9)" : "rgba(255,255,255,0.16)";
    ctx.lineWidth = 1;
    ctx.stroke();
    ctx.fillStyle = "#e6eef8";
    ctx.fillText(text, box.x + 7, box.y + box.h / 2 + 0.5);
  }
  ctx.restore();
}

// City labels appear once the camera is deep enough that dots stop overlapping.
// They carry the city name and the blocked count, and the one that was clicked
// stays pinned so the flight has a visible destination.
function drawCityLabels(
  ctx: CanvasRenderingContext2D,
  project: Screen,
  r: number,
  w: number,
  h: number,
  points: GlobePoint[],
  focus: string | null,
  picked: string | null,
) {
  const top = [...points].sort((a, b) => b.count - a.count).slice(0, 12);
  const taken: { x: number; y: number; w: number; h: number }[] = [];
  ctx.save();
  ctx.font = "500 10px Inter, ui-sans-serif, sans-serif";
  ctx.textBaseline = "middle";
  for (const pt of top) {
    const p = project(unitVec(pt.lat, pt.lon), r);
    if (p.z <= 0.12) continue;
    const dim = focus && pt.country !== focus;
    const label = `${pt.city || countryName(pt.country)}  ${pt.count.toLocaleString()}`;
    const width = Math.ceil(ctx.measureText(label).width) + 12;
    const box = { x: p.x + 9, y: p.y - 9, w: width, h: 18 };
    if (box.x + box.w > w - 6 || box.y < 6) continue;
    if (taken.some((b) => box.x < b.x + b.w + 3 && box.x + box.w + 3 > b.x && box.y < b.y + b.h + 3 && box.y + box.h + 3 > b.y)) continue;
    taken.push(box);
    ctx.globalAlpha = dim ? 0.35 : 1;
    ctx.beginPath();
    ctx.roundRect(box.x, box.y, box.w, box.h, 4);
    ctx.fillStyle = "rgba(7,15,23,0.86)";
    ctx.fill();
    ctx.strokeStyle = picked && pt.city === picked ? "rgba(94,234,212,0.85)" : "rgba(255,255,255,0.14)";
    ctx.lineWidth = 1;
    ctx.stroke();
    ctx.fillStyle = picked && pt.city === picked ? "#9ff3e4" : "#dbe6f3";
    ctx.fillText(label, box.x + 6, box.y + box.h / 2 + 0.5);
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

export type GlobeHandle = {
  // stepBack returns true when it consumed the key: city -> country -> world.
  stepBack: () => boolean;
  reset: () => void;
};

const Globe = forwardRef<GlobeHandle, {
  points: GlobePoint[];
  hits: GlobeHit[];
  // Allowed requests that landed on a sensitive endpoint, drawn as teal
  // dashed arcs: the half of the picture a blocked-only map cannot show.
  reached?: GlobePoint[];
  home: { lat: number; lon: number };
  hours?: number;
  focus?: string | null;
  onFocusChange?: (country: string | null) => void;
  variant?: "default" | "compact" | "expanded";
}>(function Globe({ points, hits, reached = [], home, hours = 1, focus: focusProp, onFocusChange, variant = "default" }, ref) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const size = useRef({ w: 0, h: 0 });
  const dots = useRef<{ x: number; y: number; r: number; pt: GlobePoint }[]>([]);
  const [visible, setVisible] = useState<Record<GroupID, boolean>>({ waf: true, dos: true, bot: true, ban: true, feed: true });
  const [localFocus, setLocalFocus] = useState<string | null>(null);
  const focus = focusProp !== undefined ? focusProp : localFocus;
  const chooseFocus = (next: string | null) => {
    if (focusProp === undefined) setLocalFocus(next);
    onFocusChange?.(next);
  };
  const [tip, setTip] = useState<Tip | null>(null);
  // The animation loop never re-runs, so it reads hover state through a ref.
  const tipRef = useRef(false);
  tipRef.current = tip !== null;
  const hoverRef = useRef(false);
  const suppressClick = useRef(false);
  const drag = useRef({ active: false, startX: 0, startY: 0, startYaw: 0, startPitch: 0, moved: false });
  // One tick keeps "attacks / min" and "last hit" counting down between polls.
  const [tick, setTick] = useState(0);

  // The camera is a goal plus the current value; the draw loop eases one into
  // the other so a click reads as a flight rather than a jump cut.
  const camRef = useRef({ yaw: 0, pitch: HOME_PITCH, zoom: 1 });
  const goalRef = useRef({ yaw: 0, pitch: HOME_PITCH, zoom: 1 });
  const [view, setView] = useState<{ country: string | null; city: string | null; zoom: number }>({
    country: null,
    city: null,
    zoom: 1,
  });
  const viewRef = useRef(view);
  viewRef.current = view;

  const state = useRef({ points, hits, reached, home, visible, focus });
  state.current.points = points;
  state.current.hits = hits;
  state.current.reached = reached;
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
    const out: Record<GroupID, number> = { waf: 0, dos: 0, bot: 0, ban: 0, feed: 0 };
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

  const reachedSum = useMemo(() => reached.reduce((n, p) => n + p.count, 0), [reached]);

  const summary = useMemo(() => {
    const parts = GROUPS.map((g) => `${counts[g.id].toLocaleString()} ${g.label}`).join(", ");
    return `Attack globe over the last ${hours} hour${hours === 1 ? "" : "s"}: ${parts}; ${reachedSum.toLocaleString()} allowed requests reached an application endpoint.`;
  }, [counts, hours, reachedSum]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let raf = 0;
    let last = performance.now();
    let live: Live[] = [];
    const seen = new Set<number>();
    let primed = false;
    const follow = { until: 0 };
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

      const cam = camRef.current;
      const goal = goalRef.current;
      const ease = paused ? 1 : Math.min(1, dt * 6);
      let turn = goal.yaw - cam.yaw;
      turn = (((turn + 180) % 360) + 360) % 360 - 180;
      cam.yaw = (cam.yaw + turn * ease + 360) % 360;
      cam.pitch += (goal.pitch - cam.pitch) * ease;
      cam.zoom += (goal.zoom - cam.zoom) * ease;
      // The slow spin only runs at world zoom; a zoomed map holds still so the
      // city an operator picked stays under the pointer.
      if (!paused && !drag.current.active && !hoverRef.current && now > follow.until && goal.zoom <= 1.01) {
        cam.yaw = (cam.yaw + dt * 4) % 360;
        goal.yaw = cam.yaw;
      }

      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const cssW = Math.round(size.current.w || canvas.clientWidth || 640);
      const cssH = Math.round(size.current.h || cssW * 0.5625);
      if (canvas.width !== Math.round(cssW * dpr) || canvas.height !== Math.round(cssH * dpr)) {
        canvas.width = Math.round(cssW * dpr);
        canvas.height = Math.round(cssH * dpr);
      }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, cssW, cssH);

      const cx = cssW / 2;
      const cy = cssH / 2;
      const r = Math.min(cssW, cssH) * 0.4 * cam.zoom;
      const project = makeProjector(cam.yaw, cam.pitch, cx, cy);

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
        glow.addColorStop(0, "rgba(56,132,255,0.14)");
        glow.addColorStop(0.45, "rgba(37,99,235,0.06)");
        glow.addColorStop(1, "rgba(11,13,16,0)");
        cache.glow = glow;
        const v = ctx.createLinearGradient(0, 0, 0, cssH);
        v.addColorStop(0, "rgba(11,13,16,0.06)");
        v.addColorStop(1, "rgba(11,13,16,0.22)");
        cache.vignette = v;
      }

      // A flat wash keeps the stage calm; threat data supplies the movement.
      if (cache.vignette) {
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
      ctx.strokeStyle = "rgba(96,165,250,0.07)";
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

      const focus = state.current.focus ? state.current.focus.toUpperCase() : null;
      const shown = state.current.points.filter((p) => state.current.visible[groupFor(p.category)]);
      const countryCounts = new Map<string, number>();
      for (const pt of shown) {
        const code = pt.country.toUpperCase();
        countryCounts.set(code, (countryCounts.get(code) ?? 0) + pt.count);
      }
      const countryMax = Math.max(1, ...countryCounts.values());
      drawCountries(ctx, project, cx, cy, r, countryCounts, countryMax, focus);

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
          if (!reduced && !tipRef.current && now > follow.until && goal.zoom <= 1.01) {
            const facing = project(unitVec(h.lat, h.lon), r);
            if (facing.z < 0.25) {
              goalRef.current.yaw = -h.lon;
              follow.until = now + 4000;
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
          dim ? 0.04 : 0.16 + weight * 0.4,
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

      // ---- reached: teal dashed arcs from a source country to the app ----
      // Drawn under the live comets and with a dash pattern, so "it got in"
      // reads as a different outcome from "it was refused" at a glance.
      const reachedShown = (state.current.reached ?? []).slice(0, 12);
      for (const pt of reachedShown) {
        const target = project(unitVec(pt.lat, pt.lon), r);
        if (target.z <= 0 || homeP.z <= 0) continue;
        const dim = focus && pt.country.toUpperCase() !== focus;
        const samples = arcFor(unitVec(pt.lat, pt.lon), homeVec);
        ctx.save();
        ctx.setLineDash([3, 4]);
        drawArc(ctx, samples, project, r, "#5eead4", dim ? 0.1 : 0.72, 1.5, 6);
        ctx.restore();
        ctx.save();
        ctx.globalAlpha = dim ? 0.2 : 0.95;
        ctx.fillStyle = "#5eead4";
        ctx.beginPath();
        ctx.arc(target.x, target.y, 2.4, 0, Math.PI * 2);
        ctx.fill();
        ctx.restore();
      }

      // ---- live hits: a comet crosses in 1.2s ----
      for (const l of live) {
        const t = Math.min(1, (now - l.born) / l.life);
        const fade = 1 - t;
        const a = unitVec(l.hit.lat, l.hit.lon);
        const samples = arcFor(a, homeVec);
        const color = colorFor(l.hit.category);
        drawArc(ctx, samples, project, r, color, 0.2 + fade * 0.65, 1.6, 6);
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
        const radius = (3 + weight * 11) / Math.sqrt(Math.max(1, cam.zoom));
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

      // A teal halo around home marks that something reached the app, even when
      // the source arcs are on the far side of the sphere.
      if (reachedShown.length > 0 && homeP.z > 0) {
        ctx.save();
        ctx.strokeStyle = "rgba(94,234,212,0.7)";
        ctx.lineWidth = 1.1;
        ctx.beginPath();
        ctx.arc(homeP.x, homeP.y, 11 + Math.sin(now2 * 2) * 1.4, 0, Math.PI * 2);
        ctx.stroke();
        ctx.restore();
      }

      if (variant === "expanded") {
        if (cam.zoom >= 1.7) {
          drawCityLabels(ctx, project, r, cssW, cssH, shown, focus, viewRef.current.city);
        }
        if (cam.zoom < 2.4) {
          drawCountryLabels(ctx, project, r, cssW, cssH, countryCounts, focus);
        }
      }

      ctx.strokeStyle = "rgba(96,165,250,0.22)";
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

  const clamp = (v: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, v));

  // flyToAngle points the camera at a coordinate. The pitch is clamped short of
  // the poles: beyond that the country shapes fold onto themselves.
  const flyToAngle = (lat: number, lon: number, zoom: number) => {
    goalRef.current.yaw = -lon;
    goalRef.current.pitch = clamp(lat * DEG, -PITCH_LIMIT, PITCH_LIMIT);
    goalRef.current.zoom = clamp(zoom, ZOOM_MIN, ZOOM_MAX);
  };

  const setZoom = (next: number) => {
    const zoom = clamp(next, ZOOM_MIN, ZOOM_MAX);
    goalRef.current.zoom = zoom;
    if (zoom === ZOOM_MIN) goalRef.current.pitch = HOME_PITCH;
    setView((v) => ({ ...v, zoom }));
  };

  const resetCamera = () => {
    goalRef.current.zoom = ZOOM_MIN;
    goalRef.current.pitch = HOME_PITCH;
    setView({ country: null, city: null, zoom: 1 });
  };

  const selectPoint = (pt: GlobePoint) => {
    const code = pt.country.toUpperCase();
    chooseFocus(code);
    flyToAngle(pt.lat, pt.lon, 3);
    setView({ country: code, city: pt.city || null, zoom: 3 });
  };

  useImperativeHandle(ref, () => ({
    stepBack: () => {
      const v = viewRef.current;
      if (v.city) {
        // Back to the country: same camera tilt, one level out.
        goalRef.current.zoom = 1.9;
        setView({ ...v, city: null, zoom: 1.9 });
        return true;
      }
      if (v.country) {
        chooseFocus(null);
        resetCamera();
        return true;
      }
      if (goalRef.current.zoom > 1.02 || Math.abs(goalRef.current.pitch - HOME_PITCH) > 0.02) {
        resetCamera();
        return true;
      }
      return false;
    },
    reset: () => {
      chooseFocus(null);
      resetCamera();
    },
  }));

  // The wheel has to be a non-passive listener: the page must not scroll while
  // the map is being zoomed under the pointer.
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || variant !== "expanded") return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const next = clamp(goalRef.current.zoom * (e.deltaY > 0 ? 1 / 1.25 : 1.25), ZOOM_MIN, ZOOM_MAX);
      goalRef.current.zoom = next;
      setView((v) => (v.zoom === next ? v : { ...v, zoom: next }));
    };
    canvas.addEventListener("wheel", onWheel, { passive: false });
    return () => canvas.removeEventListener("wheel", onWheel);
  }, [variant]);

  // Clearing the country filter from outside (the HUD chip or the map's tabs)
  // also puts the camera back, so the globe never sits zoomed on nothing.
  useEffect(() => {
    if (focusProp === null && viewRef.current.country) {
      resetCamera();
    }
    // resetCamera closes over refs only.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focusProp]);

  const onMove = (e: ReactPointerEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    hoverRef.current = true;
    if (drag.current.active) {
      const dx = e.clientX - drag.current.startX;
      const dy = e.clientY - drag.current.startY;
      if (Math.abs(dx) > 3 || Math.abs(dy) > 3) drag.current.moved = true;
      // Dragging a zoomed map moves less per pixel, so a city stays reachable.
      const gain = 0.45 / Math.sqrt(Math.max(1, camRef.current.zoom));
      goalRef.current.yaw = (drag.current.startYaw + dx * gain + 360) % 360;
      goalRef.current.pitch = clamp(drag.current.startPitch + dy * gain * 0.8, -PITCH_LIMIT, PITCH_LIMIT);
      setTip(null);
      return;
    }
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

  const pickCountry = (x: number, y: number) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const rect = canvas.getBoundingClientRect();
    const w = rect.width;
    const h = rect.height;
    const r = Math.min(w, h) * 0.4 * goalRef.current.zoom;
    const cx = w / 2;
    const cy = h / 2;
    const project = makeProjector(camRef.current.yaw, camRef.current.pitch, cx, cy);
    // Hit-testing ignores the context transform, so convert CSS pixels to backing-store pixels.
    const scale = canvas.width / rect.width;
    for (const country of COUNTRIES_V) {
      if (project(country.label, r).z <= 0.01) continue;
      const path = new Path2D();
      countryPath(path, country, project, cx, cy, r);
      if (ctx.isPointInPath(path, x * scale, y * scale)) {
        const next = focus === country.code ? null : country.code;
        chooseFocus(next);
        if (next) {
          flyToAngle(Math.asin(country.label.y) / DEG, Math.atan2(country.label.x, country.label.z) / DEG, 1.9);
          setView({ country: next, city: null, zoom: 1.9 });
        } else {
          resetCamera();
        }
        return;
      }
    }
  };

  const onDown = (e: ReactPointerEvent<HTMLCanvasElement>) => {
    if (variant !== "expanded") return;
    suppressClick.current = false;
    drag.current = {
      active: true,
      startX: e.clientX,
      startY: e.clientY,
      startYaw: goalRef.current.yaw,
      startPitch: goalRef.current.pitch,
      moved: false,
    };
    e.currentTarget.setPointerCapture(e.pointerId);
    setTip(null);
  };

  const onUp = (e: ReactPointerEvent<HTMLCanvasElement>) => {
    if (!drag.current.active) return;
    drag.current.active = false;
    suppressClick.current = drag.current.moved;
    try {
      e.currentTarget.releasePointerCapture(e.pointerId);
    } catch {
      /* pointer capture can already be gone after a cancel */
    }
  };

  const onClick = (e: ReactMouseEvent<HTMLCanvasElement>) => {
    if (suppressClick.current) {
      suppressClick.current = false;
      return;
    }
    const rect = e.currentTarget.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    for (const d of dots.current) {
      if (Math.hypot(d.x - x, d.y - y) <= d.r + 7) {
        selectPoint(d.pt);
        return;
      }
    }
    pickCountry(x, y);
  };

  const tipW = 210;
  const tipLeft = tip ? Math.min(tip.x + 14, Math.max(6, (size.current.w || 0) - tipW - 6)) : 0;

  return (
    <>
      <div className={`globe-wrap ${variant === "compact" ? "compact" : ""} ${variant === "expanded" ? "expanded" : ""}`} ref={wrapRef}>
        <canvas
          ref={canvasRef}
          role="img"
          aria-label={`World map of blocked attacks and allowed requests that reached an application in the last ${hours} hour${hours === 1 ? "" : "s"}`}
          onPointerMove={onMove}
          onPointerDown={onDown}
          onPointerUp={onUp}
          onClick={onClick}
          onPointerCancel={() => { drag.current.active = false; }}
          onPointerLeave={() => { hoverRef.current = false; if (!drag.current.active) setTip(null); }}
          style={{ cursor: variant === "expanded" ? "grab" : tip ? "pointer" : "default" }}
        />
        {variant === "expanded" && (
          <>
            <div className="globe-zoom" role="group" aria-label="Map camera">
              <button className="icon-btn" aria-label="Zoom in" title="Zoom in (+)" onClick={() => setZoom(goalRef.current.zoom * 1.4)}>
                <Icon name="plus" />
              </button>
              <button className="icon-btn" aria-label="Zoom out" title="Zoom out (−)" onClick={() => setZoom(goalRef.current.zoom / 1.4)}>
                <Icon name="minus" />
              </button>
              <button
                className="icon-btn"
                aria-label="Reset the map"
                title="Back to the world (0)"
                onClick={() => {
                  chooseFocus(null);
                  resetCamera();
                }}
              >
                <Icon name="refresh" />
              </button>
            </div>
            {(view.country || view.city || view.zoom > 1.02) && (
              <nav className="globe-crumbs" aria-label="Map location">
                <button
                  onClick={() => {
                    chooseFocus(null);
                    resetCamera();
                  }}
                >
                  World
                </button>
                {view.country && (
                  <>
                    <span aria-hidden="true">/</span>
                    <button
                      disabled={!view.city}
                      onClick={() => {
                        goalRef.current.zoom = 1.9;
                        setView((v) => ({ ...v, city: null, zoom: 1.9 }));
                      }}
                    >
                      {countryName(view.country)}
                    </button>
                  </>
                )}
                {view.city && (
                  <>
                    <span aria-hidden="true">/</span>
                    <span className="globe-crumb-now">{view.city}</span>
                  </>
                )}
                <span className="globe-zoom-label">{view.zoom.toFixed(1)}×</span>
              </nav>
            )}
          </>
        )}
        <div className="globe-hud" aria-hidden="true">
          <span className="globe-hud-rate">
            <b>{liveStats.perMin}</b> attacks/min
          </span>
          <span>
            last {hours}h · <b>{shownTotal(counts).toLocaleString()}</b> blocked
          </span>
          {liveStats.top && (
            <span>
              top {flagEmoji(liveStats.top[0])} {countryName(liveStats.top[0])} · {liveStats.top[1]}
            </span>
          )}
          {liveStats.last !== null && <span className="globe-hud-last">last hit {liveStats.last}s ago</span>}
          {focus && (
            <button className="globe-focus" onClick={() => chooseFocus(null)} title="Clear the country filter">
              {flagEmoji(focus)} {countryName(focus)} ✕
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
                {flagEmoji(tip.pt.country)} {countryName(tip.pt.country) || "unknown"}
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
      </div>
      <div className={`globe-legend-bar ${variant === "compact" ? "compact" : ""}`}>
        <div className="globe-legend" role="group" aria-label="Attack categories">
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
          {reachedSum > 0 && (
            <span className="globe-key reached" title="Allowed requests that reached a login, admin or token endpoint">
              <i style={{ background: "#2dd4bf" }} />
              Passed to app
              <b>{reachedSum.toLocaleString()}</b>
            </span>
          )}
        </div>
        {variant === "expanded" && (
          <p className="globe-footnote">
            <b>WAF block</b> = signature match. <b>DoS / rate</b> = rate, concurrency or login limit.{" "}
            <b>Bot protection</b> = user-agent filter or browser challenge. <b>Ban / scanner</b> = existing ban,
            decoy/scanner hit, or country/list/ASN deny — CrowdSec decisions are counted here because the globe feed
            does not record the ban source. <b>Threat feed</b> = IP matched a threat-intel feed.{" "}
            <b>Passed to app</b> = an allowed request that landed on a login, admin or token endpoint, drawn as a
            dashed teal arc.
          </p>
        )}
      </div>
    </>
  );
});

export default Globe;

function shownTotal(counts: Record<GroupID, number>): number {
  return GROUPS.reduce((n, g) => n + counts[g.id], 0);
}
