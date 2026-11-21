import { useEffect, useMemo, useRef, useState } from "react";
import { GlobePoint } from "../types";
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

function project(lat: number, lon: number, rotation: number, cx: number, cy: number, r: number) {
  const phi = lat * DEG;
  const lambda = (lon + rotation) * DEG;
  const x = Math.cos(phi) * Math.sin(lambda);
  const y = Math.sin(phi);
  const z = Math.cos(phi) * Math.cos(lambda);
  return { x: cx + x * r, y: cy - y * r, z };
}

type Column = { x: number; y: number; speed: number };

const MATRIX_CHARS = "01SYNACKGETPOST403DENYWAFATKSCAN";

function seedMatrix(width: number): Column[] {
  const cols: Column[] = [];
  for (let x = 8; x < width; x += 13) {
    cols.push({ x, y: Math.random() * 240, speed: 18 + Math.random() * 42 });
  }
  return cols;
}

function drawMatrix(ctx: CanvasRenderingContext2D, columns: Column[], width: number, height: number, dt: number) {
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
    ctx.fillStyle = "rgba(34,197,94,0.14)";
    ctx.fillText(ch, c.x, c.y);
    ctx.fillStyle = "rgba(134,239,172,0.22)";
    ctx.fillText(ch, c.x, c.y - 12);
  }
  // A very faint vignette keeps the matrix from competing with the arcs.
  const v = ctx.createLinearGradient(0, 0, 0, height);
  v.addColorStop(0, "rgba(11,13,16,0.06)");
  v.addColorStop(1, "rgba(11,13,16,0.22)");
  ctx.fillStyle = v;
  ctx.fillRect(0, 0, width, height);
}

function drawLand(ctx: CanvasRenderingContext2D, rotation: number, cx: number, cy: number, r: number) {
  for (const ring of LAND) {
    const points = ring.map(([lon, lat]) => project(lat, lon, rotation, cx, cy, r));
    const allVisible = points.every((p) => p.z > 0);
    ctx.beginPath();
    let started = false;
    for (const p of points) {
      if (p.z <= 0) {
        started = false;
        continue;
      }
      if (!started) {
        ctx.moveTo(p.x, p.y);
        started = true;
      } else {
        ctx.lineTo(p.x, p.y);
      }
    }
    if (allVisible) {
      ctx.closePath();
      ctx.fillStyle = "rgba(37,99,235,0.12)";
      ctx.fill();
    }
    ctx.strokeStyle = "rgba(96,165,250,0.34)";
    ctx.lineWidth = 0.8;
    ctx.stroke();
  }
}

export default function Globe({ points, home }: { points: GlobePoint[]; home: { lat: number; lon: number } }) {
  const ref = useRef<HTMLCanvasElement | null>(null);
  const [visible, setVisible] = useState<Record<GroupID, boolean>>({
    waf: true,
    dos: true,
    ban: true,
    feed: true,
  });
  const state = useRef({ points, home, visible, rotation: 0 });
  state.current.points = points;
  state.current.home = home;
  state.current.visible = visible;

  const counts = useMemo(() => {
    const out: Record<GroupID, number> = { waf: 0, dos: 0, ban: 0, feed: 0 };
    for (const p of points) out[groupFor(p.category)] += p.count;
    return out;
  }, [points]);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    let raf = 0;
    let last = performance.now();
    let columns: Column[] = [];
    let columnWidth = 0;

    const draw = (now: number) => {
      const dt = Math.min(0.05, (now - last) / 1000);
      last = now;
      const reduced = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
      if (!reduced && document.visibilityState === "visible") {
        state.current.rotation = (state.current.rotation + dt * 4) % 360;
      }
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const cssW = canvas.clientWidth || 640;
      const cssH = Math.round(cssW * 0.56);
      if (canvas.width !== Math.round(cssW * dpr) || canvas.height !== Math.round(cssH * dpr)) {
        canvas.width = Math.round(cssW * dpr);
        canvas.height = Math.round(cssH * dpr);
        columns = [];
      }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, cssW, cssH);

      if (columns.length === 0 || Math.abs(columnWidth - cssW) > 1) {
        columnWidth = cssW;
        columns = seedMatrix(cssW);
      }
      if (!reduced && document.visibilityState === "visible") drawMatrix(ctx, columns, cssW, cssH, dt);

      const cx = cssW / 2;
      const cy = cssH / 2;
      const r = Math.min(cssW, cssH) * 0.40;
      const rot = state.current.rotation;

      const glow = ctx.createRadialGradient(cx, cy, r * 0.2, cx, cy, r * 1.25);
      glow.addColorStop(0, "rgba(37,99,235,0.20)");
      glow.addColorStop(0.6, "rgba(15,23,42,0.06)");
      glow.addColorStop(1, "rgba(11,13,16,0)");
      ctx.fillStyle = glow;
      ctx.fillRect(0, 0, cssW, cssH);

      ctx.strokeStyle = "rgba(59,130,246,0.28)";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.stroke();

      ctx.strokeStyle = "rgba(59,130,246,0.13)";
      for (const lat of [-60, -30, 0, 30, 60]) {
        ctx.beginPath();
        let started = false;
        for (let lon = 0; lon <= 360; lon += 4) {
          const p = project(lat, lon, rot, cx, cy, r);
          if (p.z <= 0) {
            started = false;
            continue;
          }
          if (!started) {
            ctx.moveTo(p.x, p.y);
            started = true;
          } else {
            ctx.lineTo(p.x, p.y);
          }
        }
        ctx.stroke();
      }
      for (let lon = 0; lon < 360; lon += 30) {
        ctx.beginPath();
        let started = false;
        for (let lat = -88; lat <= 88; lat += 4) {
          const p = project(lat, lon, rot, cx, cy, r);
          if (p.z <= 0) {
            started = false;
            continue;
          }
          if (!started) {
            ctx.moveTo(p.x, p.y);
            started = true;
          } else {
            ctx.lineTo(p.x, p.y);
          }
        }
        ctx.stroke();
      }

      drawLand(ctx, rot, cx, cy, r);

      const homeP = project(state.current.home.lat, state.current.home.lon, rot, cx, cy, r);
      const now2 = now / 1000;
      const shown = state.current.points.filter((p) => state.current.visible[groupFor(p.category)]).slice(0, 140);

      for (let i = 0; i < shown.length; i++) {
        const pt = shown[i];
        const target = project(pt.lat, pt.lon, rot, cx, cy, r);
        const alpha = Math.min(0.85, 0.22 + Math.log10(1 + pt.count) * 0.22);
        if (target.z > 0) {
          ctx.fillStyle = colorFor(pt.category);
          ctx.globalAlpha = alpha;
          ctx.beginPath();
          ctx.arc(target.x, target.y, 1.8 + Math.min(3.2, Math.log10(1 + pt.count) * 1.1), 0, Math.PI * 2);
          ctx.fill();
          ctx.globalAlpha = 1;
        }
        if (target.z > 0 && homeP.z > 0) {
          const mx = (target.x + homeP.x) / 2;
          const my = (target.y + homeP.y) / 2;
          const dx = homeP.x - target.x;
          const dy = homeP.y - target.y;
          const len = Math.hypot(dx, dy) || 1;
          const lift = Math.min(90, len * 0.28);
          const ctrlX = mx - (dy / len) * lift * 0.35;
          const ctrlY = my + (dx / len) * lift * 0.35 - 18;
          ctx.strokeStyle = colorFor(pt.category);
          ctx.globalAlpha = alpha * 0.55;
          ctx.lineWidth = 1.1;
          ctx.beginPath();
          ctx.moveTo(target.x, target.y);
          ctx.quadraticCurveTo(ctrlX, ctrlY, homeP.x, homeP.y);
          ctx.stroke();

          // A pulse travelling along the arc makes old aggregates read as a
          // live stream without inventing synthetic events.
          const t = reduced ? 0.55 : (now2 * 0.22 + i * 0.13) % 1;
          const u = 1 - t;
          const px = u * u * target.x + 2 * u * t * ctrlX + t * t * homeP.x;
          const py = u * u * target.y + 2 * u * t * ctrlY + t * t * homeP.y;
          ctx.fillStyle = "#dbeafe";
          ctx.globalAlpha = 0.85;
          ctx.beginPath();
          ctx.arc(px, py, 1.45, 0, Math.PI * 2);
          ctx.fill();
          ctx.globalAlpha = 1;
        }
      }

      if (homeP.z > 0) {
        ctx.fillStyle = "#93c5fd";
        ctx.beginPath();
        ctx.arc(homeP.x, homeP.y, 3.2, 0, Math.PI * 2);
        ctx.fill();
        ctx.strokeStyle = "rgba(147,197,253,0.5)";
        ctx.beginPath();
        ctx.arc(homeP.x, homeP.y, 7 + Math.sin(now2 * 2) * 1.6, 0, Math.PI * 2);
        ctx.stroke();
      }

      raf = requestAnimationFrame(draw);
    };
    raf = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(raf);
  }, []);

  return (
    <div className="globe-wrap">
      <canvas ref={ref} role="img" aria-label="World map of recent blocked attacks" />
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
