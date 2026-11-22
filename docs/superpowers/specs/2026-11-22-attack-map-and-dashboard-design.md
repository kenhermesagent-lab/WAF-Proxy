# Dashboard metrics and attack map — design

**Date:** 2026-11-22
**Status:** approved for implementation

## Intent

Make the dashboard’s traffic picture readable at a glance without losing the spinning globe, and make the opened attack map geographic instead of a blue sphere.

## Goals

- A 196px navigation rail (56px collapsed) instead of 236px.
- Six KPI cards in a 3×2 grid:
  1. Proxy traffic — inbound left, outbound right
  2. Requests
  3. Blocked
  4. Sessions
  5. Server & other — inbound left, outbound right
  6. Request budget — `inflight / max_inflight`, shed count
- Keep the existing canvas globe and its spin, arcs, dots and hover behaviour.
- Draw country boundaries and attack-volume fills on the globe.
- Keep labels off in the compact dashboard card.
- In the opened map, label the busiest visible countries and let the admin drag the globe, select a country, and read its attack totals and recent events.
- Every country code in the picker must map to at least one shape.

## Non-goals

- No new mapping library or runtime tile/GeoJSON request.
- No country labels in the compact card.
- No changes to the metrics API.
- No per-country historical series beyond what the existing events API returns.

## Constraints

- Existing React/canvas renderer, dark-only console.
- The country dataset ships in the bundle; keep it simplified.
- The compact globe must stay readable at dashboard width.
- The dashboard already receives `proxy`, `host`, `sessions`, `inflight`, `max_inflight` and `shed`.

## Approaches considered

- **Six across:** rejected; paired values become too narrow at 1440px.
- **Four cards with nested pairs:** rejected; hides the server/proxy distinction.
- **3×2 with paired directional cards:** selected; enough width for values and totals.
- **Map library / vector tiles:** rejected; adds a dependency and a runtime request for a 60px globe.
- **Static map image:** rejected; loses the existing motion and hit-testing.
- **Bundled simplified country rings:** selected; reuses the canvas renderer and keeps the globe self-contained.

## Selected design

### Navigation

236px becomes 196px; collapsed rail becomes 56px. Mobile drawer stays 250px. Nav rows compress to 32px; labels and icons remain legible.

### Metrics

Three equal columns, two rows. Pair cards split into two halves with a divider. Inbound is always left, outbound right. The request-budget card shows a volume bar and refused count. Existing `Spark` components remain where the metric has a history.

### Globe geometry

Country rings are bundled as a generated TypeScript module. At render time they are converted to unit vectors once, like the existing land rings. Each frame:

- non-attacked countries: steel-blue fill, faint border;
- attacked countries: amber→red fill weighted by blocked count;
- focused country: stronger border, others dimmed;
- existing graticule, limb shading, arcs and dots remain.

The compact variant draws borders and fills only. The expanded variant adds labels for the top six visible countries, with collision avoidance.

### Globe interaction

On the expanded variant, pointer drag changes the globe’s longitude. Auto-spin pauses while dragging and resumes on release. A drag threshold prevents accidental selection. A click without movement hit-tests the visible country polygons and selects the country; clicking the selected country clears the filter.

The right panel keeps the ranked region list. With a country selected it shows that country’s blocked total and recent events, using the existing `/api/events?country=` query.

### Map layout

The drawer uses the full content width (`calc(100vw - 196px)` on desktop), with a fixed 320px right rail. The globe absorbs the remaining width. Range and close controls stay in the header/toolbar.

## Country data

- Base: Natural Earth 1:50m admin-0 countries.
- Supplement: Natural Earth 1:10m admin-0 map units for codes absent from 50m, including small dependencies.
- Map U.S. minor outlying atolls to `UM`.
- Simplify large rings with Douglas–Peucker; keep small rings intact enough to render.
- Store `COUNTRY_SHAPES: Record<string, Ring[]>` and `COUNTRY_LABELS: Record<string, [lon, lat]>` in `web/src/countries-geo.ts`.
- A Vitest test imports the picker codes and fails on any code with no rings.

## Verification

- `npm test` including the country coverage test.
- `npm run build` (TS + Vite).
- Browser check at desktop and 390px: six cards, drag, click a country, event panel, Open map, close, labels off in compact.
- Report anything not exercised.
