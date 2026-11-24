import { useId } from "react";
import { Load } from "../types";
import { fmtBytes } from "../ui";

// The dial runs 240° clockwise from the bottom left, leaving the bottom of the
// circle for the percentage. The last eighth of it is the redline.
const START = 150;
const SWEEP = 240;
const REDLINE = 0.88;

function polar(radius: number, deg: number): [number, number] {
  const a = (deg * Math.PI) / 180;
  return [44 + radius * Math.cos(a), 44 + radius * Math.sin(a)];
}

function arc(radius: number, from: number, to: number): string {
  const [x0, y0] = polar(radius, from);
  const [x1, y1] = polar(radius, to);
  return `M ${x0} ${y0} A ${radius} ${radius} 0 ${to - from > 180 ? 1 : 0} 1 ${x1} ${y1}`;
}

function Gauge({ label, pct, caption }: { label: string; pct: number; caption: string }) {
  const id = useId().replace(/:/g, "");
  const value = Math.max(0, Math.min(100, Math.round(pct)));
  const hot = value >= REDLINE * 100;
  const [nx, ny] = polar(27, START + (SWEEP * value) / 100);
  const filled = arc(33, START, START + (SWEEP * value) / 100);
  return (
    <div className="gauge" role="img" aria-label={`${label} ${value}% · ${caption}`}>
      <svg viewBox="0 0 88 88" width="82" height="82" aria-hidden="true">
        <defs>
          <linearGradient id={`g${id}`} x1="0" y1="1" x2="1" y2="0">
            <stop offset="0" stopColor="#34d399" />
            <stop offset="1" stopColor="#22d3ee" />
          </linearGradient>
          <filter id={`f${id}`} x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="2.4" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        {/* The ring glows dimly all the way round; the lit part is the value. */}
        <g filter={`url(#f${id})`} opacity=".35">
          <path d={arc(33, START, START + SWEEP)} fill="none" stroke={`url(#g${id})`} strokeWidth="5" strokeLinecap="round" />
        </g>
        <path d={arc(33, START, START + SWEEP)} fill="none" stroke="var(--border-soft)" strokeWidth="6" strokeLinecap="round" />
        <path d={arc(33, START + SWEEP * REDLINE, START + SWEEP)} fill="none" stroke="var(--danger)" strokeWidth="6" strokeOpacity=".5" />
        <path
          d={filled}
          fill="none"
          stroke={hot ? "var(--danger)" : `url(#g${id})`}
          strokeWidth="5"
          strokeLinecap="round"
          strokeDasharray="4 5"
          filter={`url(#f${id})`}
        />
        {[0, 1, 2, 3, 4, 5, 6, 7, 8].map((i) => {
          const deg = START + (SWEEP * i) / 8;
          const [x0, y0] = polar(27, deg);
          const [x1, y1] = polar(30.5, deg);
          return <line key={i} x1={x0} y1={y0} x2={x1} y2={y1} stroke="#6ee7b7" strokeWidth="1.2" strokeOpacity=".55" />;
        })}
        {/* A short streak lapping the lit arc; the whole dial stays still. */}
        <path
          className="gauge-flow"
          d={filled}
          pathLength="100"
          fill="none"
          stroke={hot ? "#ffd9dd" : "#eafff6"}
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeDasharray="5 95"
          filter={`url(#f${id})`}
        />
        <line x1="44" y1="44" x2={nx} y2={ny} stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
        <circle cx="44" cy="44" r="3.4" fill="var(--bg-elev)" stroke="#6ee7b7" strokeWidth="1.2" />
        <text x="44" y="74" textAnchor="middle" fontSize="14" fontWeight="600" fill="currentColor">
          {value}%
        </text>
      </svg>
      <div className="gauge-cap">{caption}</div>
    </div>
  );
}

// What the host has left: CPU against its cores, memory against its RAM. The
// numbers come in the same one-second frame as the traffic, so the needles move
// with the dashboard instead of on their own timer.
export default function UsageCard({ load }: { load: Load | null }) {
  if (!load) return <div className="skeleton kpi" />;
  const mem = load.mem_total ? (load.mem_used / load.mem_total) * 100 : 0;
  return (
    <div className="kpi">
      <div className="kpi-label">CPU / Memory</div>
      <div className="usage-pair">
        <Gauge label="CPU" pct={load.cpu_percent} caption={load.cores ? `${load.cores} vCPU` : "host CPU"} />
        <Gauge label="Memory" pct={mem} caption={`${fmtBytes(load.mem_used)} / ${fmtBytes(load.mem_total)}`} />
      </div>
    </div>
  );
}
