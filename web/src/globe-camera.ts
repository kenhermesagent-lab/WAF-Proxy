// Camera maths for the attack globe, kept out of the component so the projection
// can be tested without a canvas.

export const DEG = Math.PI / 180;

export type V3 = { x: number; y: number; z: number };

export function unitVec(lat: number, lon: number): V3 {
  const phi = lat * DEG;
  const lambda = lon * DEG;
  return { x: Math.cos(phi) * Math.sin(lambda), y: Math.sin(phi), z: Math.cos(phi) * Math.cos(lambda) };
}

export type Screen = (v: V3, radius: number) => { x: number; y: number; z: number };

// The camera turns around the poles first (yaw) and then tilts (pitch), so a
// click can put any city in the middle of the sphere instead of only bringing
// its meridian to the front.
export function makeProjector(yaw: number, pitch: number, cx: number, cy: number): Screen {
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

export const ZOOM_MIN = 1;
export const ZOOM_MAX = 4.5;
// Pitch is kept in degrees, like yaw; only the projector converts to radians.
export const PITCH_LIMIT = 65;
export const HOME_PITCH = 3;

export function clamp(v: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, v));
}

// cameraFor is the angle pair that centres a coordinate. Latitude is clamped
// short of the poles, where country outlines fold onto themselves.
export function cameraFor(lat: number, lon: number): { yaw: number; pitch: number } {
  return { yaw: -lon, pitch: clamp(lat, -PITCH_LIMIT, PITCH_LIMIT) };
}
