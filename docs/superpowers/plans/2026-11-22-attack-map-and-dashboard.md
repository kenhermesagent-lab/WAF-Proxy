# Dashboard metrics and attack map — plan

1. **Navigation width**
   - Change `.sidebar` from 236px to 196px and collapsed rail from 64px to 56px.
   - Tighten nav row height and padding without changing the mobile drawer.

2. **Six KPI cards**
   - Replace the four-card block in `Dashboard.tsx` with a 3×2 grid.
   - Add paired proxy/server cards; keep Requests, Blocked, Sessions and Request budget.
   - Add only the CSS needed for the pair layout and the 3×2 breakpoints.

3. **Country geometry**
   - Generate `web/src/countries-geo.ts` from Natural Earth 50m + 10m supplements.
   - Include labels and provenance comment.
   - Add `countries-geo.test.ts` asserting every `COUNTRIES` code has rings.
   - Run the test before touching the globe.

4. **Globe rendering**
   - Replace land-only drawing with country fills and borders.
   - Heat attacked countries by blocked volume; dim non-focused countries.
   - Keep labels off for `compact`; draw top visible labels for `expanded`.

5. **Globe interaction**
   - Add pointer drag on `expanded`; pause auto-spin during drag.
   - Suppress click after a drag.
   - Hit-test visible country polygons on click; set the existing country focus.
   - Verify a click opens that country’s right-panel events.

6. **Map layout**
   - Expand the drawer to the available content width and keep the 320px region rail.
   - Keep the current range controls and close behaviour.

7. **Checks and demo**
   - `cd web && npm test && npm run build`.
   - Use the running mock API + Vite server.
   - Check six cards at desktop, map drag/selection, compact labels absent, 390px stack.
   - Leave the work uncommitted and show the demo.
