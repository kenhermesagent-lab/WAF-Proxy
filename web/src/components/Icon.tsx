import type { SVGProps } from "react";

export type IconName =
  | "dashboard" | "chart" | "proxies" | "play" | "shield" | "radio" | "logs"
  | "alert" | "lock" | "intel" | "crowdsec" | "certificate" | "terminal"
  | "mail" | "upload" | "network" | "settings" | "user" | "power" | "search"
  | "globe" | "map" | "check" | "x" | "info" | "plus" | "trash" | "edit"
  | "refresh" | "external" | "download" | "menu" | "chevronDown" | "chevronLeft"
  | "chevronRight" | "collapse" | "expand" | "clock" | "server" | "activity"
  | "arrowUp" | "arrowDown" | "filter" | "file" | "help" | "key";

const PATHS: Record<IconName, string[]> = {
  dashboard: ["M3 3h7v7H3z", "M14 3h7v4h-7z", "M14 11h7v10h-7z", "M3 14h7v7H3z"],
  chart: ["M3 20V10", "M9 20V4", "M15 20v-7", "M21 20V7"],
  proxies: ["M4 7h13l-3-3", "M20 17H7l3 3"],
  play: ["M7 4.5v15l13-7.5z"],
  shield: ["M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z"],
  radio: ["M12 12a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3", "M8.5 8.5a5 5 0 0 0 0 7", "M15.5 8.5a5 5 0 0 1 0 7", "M5.6 5.6a9 9 0 0 0 0 12.8", "M18.4 5.6a9 9 0 0 1 0 12.8"],
  logs: ["M8 6h13", "M8 12h13", "M8 18h13", "M3.5 6h.01", "M3.5 12h.01", "M3.5 18h.01"],
  alert: ["M12 3.5 21 19H3z", "M12 9v4", "M12 16h.01"],
  lock: ["M6 10V8a6 6 0 0 1 12 0v2", "M5 10h14v10H5z", "M12 14v2"],
  intel: ["M12 3l2.2 4.5 5 .7-3.6 3.5.9 4.9-4.5-2.3-4.5 2.3.9-4.9L4.8 8.2l5-.7z"],
  crowdsec: ["M12 3l7.5 4.2v9.6L12 21l-7.5-4.2V7.2z", "M12 8v8", "M8.5 10l7 4", "M15.5 10l-7 4"],
  certificate: ["M6 3h12v13H6z", "M9 7h6", "M9 10h4", "M9 16.5v4l3-1.8 3 1.8v-4"],
  terminal: ["M4 5h16v14H4z", "M8 9l2.5 2.5L8 14", "M13 14h3"],
  mail: ["M3 6h18v12H3z", "M3 7l9 6 9-6"],
  upload: ["M12 16V4", "M7 9l5-5 5 5", "M4 20h16"],
  network: ["M12 3a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5", "M5 16a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5", "M19 16a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5", "M12 8v5", "M7 16l4-3", "M17 16l-4-3"],
  settings: ["M4 6h9", "M17 6h3", "M13 3.5v5", "M4 12h4", "M12 12h8", "M8 9.5v5", "M4 18h9", "M17 18h3", "M13 15.5v5"],
  user: ["M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8", "M4.5 21a7.5 7.5 0 0 1 15 0"],
  power: ["M12 3v9", "M7 6a8 8 0 1 0 10 0"],
  search: ["M10.5 17a6.5 6.5 0 1 0 0-13 6.5 6.5 0 0 0 0 13", "M15.5 15.5 21 21"],
  globe: ["M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18", "M3.5 12h17", "M12 3c3 2.5 4.5 5.5 4.5 9s-1.5 6.5-4.5 9c-3-2.5-4.5-5.5-4.5-9S9 5.5 12 3"],
  map: ["M3 6.5 9 4l6 2.5L21 4v13.5L15 20l-6-2.5L3 20z", "M9 4v13.5", "M15 6.5V20"],
  check: ["M4 12.5l5 5L20 6.5"],
  x: ["M6 6l12 12", "M18 6 6 18"],
  info: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18", "M12 11v5", "M12 8h.01"],
  plus: ["M12 5v14", "M5 12h14"],
  trash: ["M4 7h16", "M9 7V5h6v2", "M6 7l1 13h10l1-13", "M10 11v5", "M14 11v5"],
  edit: ["M4 20h4L20 8l-4-4L4 16z", "M14 6l4 4"],
  refresh: ["M20 11a8 8 0 1 0-2.3 5.7", "M20 4v7h-7"],
  external: ["M14 4h6v6", "M20 4 10 14", "M18 14v6H4V6h6"],
  download: ["M12 4v12", "M7 11l5 5 5-5", "M4 20h16"],
  menu: ["M4 7h16", "M4 12h16", "M4 17h16"],
  chevronDown: ["M6 9l6 6 6-6"],
  chevronLeft: ["M14 6l-6 6 6 6"],
  chevronRight: ["M10 6l6 6-6 6"],
  collapse: ["M9 6l6 6-6 6", "M19 4v16"],
  expand: ["M15 6l-6 6 6 6", "M5 4v16"],
  clock: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18", "M12 7v5l3 2"],
  server: ["M4 4h16v6H4z", "M4 14h16v6H4z", "M8 7h.01", "M8 17h.01"],
  activity: ["M3 12h4l2.5-7 5 14 2.5-7h4"],
  arrowUp: ["M12 19V5", "M6 11l6-6 6 6"],
  arrowDown: ["M12 5v14", "M6 13l6 6 6-6"],
  filter: ["M3 5h18l-7 8v6l-4 2v-8z"],
  file: ["M6 3h8l4 4v14H6z", "M14 3v4h4"],
  help: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18", "M9.5 9a2.5 2.5 0 1 1 3.6 2.3c-.7.4-1.1 1-1.1 1.7", "M12 17h.01"],
  key: ["M14 10a4 4 0 1 0-3.4 4l1.4 1.4H14v2h2v2h3v-3l-5-5", "M7.5 7.5h.01"],
};

export default function Icon({
  name,
  size = 16,
  ...rest
}: { name: IconName; size?: number } & Omit<SVGProps<SVGSVGElement>, "name">) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...rest}
    >
      {PATHS[name].map((d, i) => <path key={i} d={d} />)}
    </svg>
  );
}
