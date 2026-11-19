import { useEffect, useRef } from "react";
import { GlobePoint } from "../types";

const COLORS: Record<string, string> = {
  waf: "#ef4444",
  sqli: "#ef4444",
  xss: "#f97316",
  rce: "#ef4444",
  "php-injection": "#ef4444",
  "unix-shell": "#ef4444",
  lfi: "#f59e0b",
  scanner: "#a855f7",
  "country-block": "#8b5cf6",
  "asn-block": "#6366f1",
  "asn": "#6366f1",
  dos: "#f59e0b",
  "temp-ban": "#a855f7",
  "permanent-ban": "#ec4899",
  feed: "#14b8a6",
  "bot-challenge": "#f97316",
  decoy: "#ec4899",
};

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

export default function Globe({ points, home }: { points: GlobePoint[]; home: { lat: number; lon: number } }) {
  const ref = useRef<HTMLCanvasElement | null>(null);
  const state = useRef({ points, home, rotation: 0 });
  state.current.points = points;
  state.current.home = home;

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    let raf = 0;
    let last = performance.now();

    const draw = (now: number) => {
      const dt = Math.min(0.05, (now - last) / 1000);
      last = now;
      if (document.visibilityState === "visible") {
        state.current.rotation = (state.current.rotation + dt * 4) % 360;
      }
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const cssW = canvas.clientWidth || 640;
      const cssH = Math.round(cssW * 0.56);
      if (canvas.width !== Math.round(cssW * dpr) || canvas.height !== Math.round(cssH * dpr)) {
        canvas.width = Math.round(cssW * dpr);
        canvas.height = Math.round(cssH * dpr);
      }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, cssW, cssH);

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

      const homeP = project(state.current.home.lat, state.current.home.lon, rot, cx, cy, r);
      const now2 = now / 1000;
      const maxArcs = 90;
      const shown = state.current.points.slice(0, maxArcs);

      for (const pt of shown) {
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
      <canvas ref={ref} />
      <div className="globe-legend">
        <span><i style={{ background: "#ef4444" }} />WAF block</span>
        <span><i style={{ background: "#f59e0b" }} />DoS / rate</span>
        <span><i style={{ background: "#a855f7" }} />ban / scanner</span>
        <span><i style={{ background: "#14b8a6" }} />threat feed</span>
      </div>
    </div>
  );
}
