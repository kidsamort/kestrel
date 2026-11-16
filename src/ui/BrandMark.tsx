/**
 * Kestrel mark: four round-capped strokes through the centre, which read as an
 * eight-point star. Drawn with `currentColor`, so the tile owns the colour — the
 * default blue accent paints it `--on-accent` (white on the default theme).
 *
 * Geometry is the supplied artwork normalised to a 100x100 box: stroke width 19,
 * round caps, arms from 15 to 85.
 */
const ARMS: readonly [number, number, number, number][] = [
  [15, 50, 85, 50],
  [25.251, 74.749, 74.749, 25.251],
  [50, 85, 50, 15],
  [74.749, 74.749, 25.251, 25.251],
];

export function BrandMark({ size = 22 }: { size?: number }) {
  return (
    <span className="mark" style={{ width: size, height: size }} aria-hidden="true">
      <svg
        viewBox="0 0 100 100"
        width={Math.round(size * 0.72)}
        height={Math.round(size * 0.72)}
        fill="none"
        stroke="currentColor"
        strokeWidth={19}
        strokeLinecap="round"
      >
        {ARMS.map(([x1, y1, x2, y2]) => (
          <line key={`${x1}-${y1}`} x1={x1} y1={y1} x2={x2} y2={y2} />
        ))}
      </svg>
    </span>
  );
}
