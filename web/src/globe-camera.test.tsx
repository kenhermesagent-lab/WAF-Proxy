import { describe, expect, it } from "vitest";
import { PITCH_LIMIT, cameraFor, makeProjector, unitVec } from "./globe-camera";

// A click flies the camera with cameraFor and the canvas projects with
// makeProjector. If the two disagree, the picked city lands off-centre or on the
// far side of the sphere, so the pair is checked together.
describe("globe camera", () => {
  it.each([
    ["Moscow", 55.75, 37.62],
    ["Sao Paulo", -23.55, -46.63],
    ["Singapore", 1.35, 103.82],
    ["Reykjavik", 64.15, -21.94],
    ["Sydney", -33.87, 151.21],
  ])("centres %s", (_name, lat, lon) => {
    const at = cameraFor(lat, lon);
    const project = makeProjector(at.yaw, at.pitch, 320, 200);
    const p = project(unitVec(lat, lon), 180);
    expect(p.x).toBeCloseTo(320, 6);
    expect(p.y).toBeCloseTo(200, 6);
    expect(p.z).toBeCloseTo(1, 6);
  });

  it("keeps the far side of the sphere behind the camera", () => {
    const at = cameraFor(0, 0);
    const project = makeProjector(at.yaw, at.pitch, 0, 0);
    const back = project(unitVec(0, 180), 100);
    expect(back.z).toBeLessThan(-0.9);
  });

  it("stops short of the poles where the outlines fold", () => {
    const north = cameraFor(89, 10);
    expect(north.pitch).toBeCloseTo(PITCH_LIMIT, 6);
    const south = cameraFor(-89, 10);
    expect(south.pitch).toBeCloseTo(-PITCH_LIMIT, 6);
  });

  it("keeps the tilt sign so the north pole is drawn above the equator", () => {
    const project = makeProjector(0, 0, 0, 0);
    expect(project(unitVec(45, 0), 100).y).toBeLessThan(0);
  });
});
