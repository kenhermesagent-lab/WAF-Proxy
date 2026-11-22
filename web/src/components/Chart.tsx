import { useMemo, useState } from "react";

export type Series = { label: string; color: string; values: number[]; area?: boolean };

function niceMax(v: number): number {
  if (!Number.isFinite(v) || v <= 0) return 1;
  const pow = Math.pow(10, Math.floor(Math.log10(v)));
  const n = v / pow;
  const step = n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10;
  return step * pow;
}

/**
 * Time-series line/area chart with y/x axes, grid, legend and a hover
 * crosshair. Axis labels are HTML so they never stretch when the SVG scales.
 */
export default function Chart({
  series,
  labels,
  height = 220,
  format = (n) => n.toLocaleString(),
  yTicks = 4,
  xLabels = 5,
  tooltipTitle,
  legend = true,
}: {
  series: Series[];
  labels: string[];
  height?: number;
  format?: (n: number) => string;
  yTicks?: number;
  xLabels?: number;
  tooltipTitle?: (label: string) => string;
  legend?: boolean;
}) {
  const [hover, setHover] = useState<number | null>(null);
  const W = 1000;
  const pad = { top: 10, right: 8, bottom: 4, left: 4 };
  const plotW = W - pad.left - pad.right;
  const count = Math.max(1, labels.length);
  const max = useMemo(() => niceMax(Math.max(0, ...series.flatMap((s) => s.values))), [series]);

  const x = (i: number) => pad.left + (count === 1 ? plotW / 2 : (i / (count - 1)) * plotW);
  const y = (v: number) => pad.top + 100 - (Math.min(max, Math.max(0, v)) / max) * 90;

  const ticks = Array.from({ length: yTicks + 1 }, (_, i) => (max * i) / yTicks);
  const labelStride = Math.max(1, Math.ceil((labels.length - 1) / Math.max(1, xLabels - 1)));
  const labelIndexes = labels.map((_, i) => i).filter((i) => i % labelStride === 0 || i === labels.length - 1);

  const onMove = (e: React.PointerEvent<HTMLDivElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const px = ((e.clientX - rect.left) / rect.width) * W;
    const ratio = Math.min(1, Math.max(0, (px - pad.left) / plotW));
    setHover(Math.round(ratio * (count - 1)));
  };

  if (labels.length === 0 || series.every((s) => s.values.length === 0)) {
    return <div className="chart-empty">No data for this range.</div>;
  }

  return (
    <div className="chart">
      <div className="chart-frame" style={{ display: "flex", gap: 8 }}>
        <div className="chart-y" style={{ width: 48, height, position: "relative", flex: "0 0 48px" }}>
          {ticks.map((t, i) => (
            <span
              key={i}
              className="axis-label"
              style={{ position: "absolute", right: 0, top: `calc(${(y(t) / 110) * 100}% - 7px)`, whiteSpace: "nowrap" }}
            >
              {format(t)}
            </span>
          ))}
        </div>
        <div
          style={{ position: "relative", flex: 1, minWidth: 0, height }}
          onPointerMove={onMove}
          onPointerLeave={() => setHover(null)}
        >
          <svg viewBox={`0 0 ${W} 110`} preserveAspectRatio="none" style={{ width: "100%", height: "100%" }} role="img" aria-label={`${series.map((s) => s.label).join(", ")} over ${labels.length} points`}>
            {ticks.map((t, i) => (
              <line key={i} className="grid-line" x1={0} x2={W} y1={y(t)} y2={y(t)} vectorEffect="non-scaling-stroke" />
            ))}
            {series.map((s) => {
              if (s.values.length === 0) return null;
              const pts = s.values.map((v, i) => `${x(i)},${y(v)}`).join(" ");
              const area = `0,106 ${pts} ${x(s.values.length - 1)},106`;
              return (
                <g key={s.label}>
                  {s.area && <polygon className="series-area" points={area} fill={s.color} />}
                  <polyline className="series-line" points={pts} stroke={s.color} vectorEffect="non-scaling-stroke" />
                </g>
              );
            })}
            {hover !== null && hover >= 0 && hover < labels.length && (
              <g>
                <line className="hover-line" x1={x(hover)} x2={x(hover)} y1={0} y2={106} vectorEffect="non-scaling-stroke" />
                {series.map((s) => (
                  <circle key={s.label} cx={x(hover)} cy={y(s.values[hover] ?? 0)} r={3.2} fill={s.color} stroke="#0a0c10" strokeWidth={1.4} vectorEffect="non-scaling-stroke" />
                ))}
              </g>
            )}
          </svg>
          {hover !== null && hover >= 0 && hover < labels.length && (
            <div
              className="chart-tip"
              style={{
                left: `${(x(hover) / W) * 100}%`,
                top: 0,
                transform: hover > labels.length / 2 ? "translateX(calc(-100% - 12px))" : "translateX(12px)",
              }}
            >
              <div className="chart-tip-head">{tooltipTitle ? tooltipTitle(labels[hover]) : labels[hover]}</div>
              {series.map((s) => (
                <div className="chart-tip-row" key={s.label}>
                  <span>{s.label}</span>
                  <b>{format(s.values[hover] ?? 0)}</b>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
      <div className="chart-x" style={{ marginLeft: 56, display: "flex", justifyContent: "space-between", marginTop: 5 }}>
        {labelIndexes.map((i, n) => (
          <span key={i} className="axis-label" style={{ textAlign: n === 0 ? "left" : n === labelIndexes.length - 1 ? "right" : "center" }}>
            {labels[i]}
          </span>
        ))}
      </div>
      {legend && (
        <div className="chart-legend">
          {series.map((s) => (
            <span key={s.label}><i style={{ background: s.color }} /> {s.label}</span>
          ))}
        </div>
      )}
    </div>
  );
}
