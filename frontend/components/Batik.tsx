/**
 * Mega Mendung batik motifs (Cirebon cloud scallops).
 *
 * Decorative only — every node is `aria-hidden`. Used at "Halus" intensity:
 * a thin scalloped divider and a soft hero ornament. The signature of Mega
 * Mendung is the layered cloud + the colour gradient, so the strokes ride the
 * `mega-mendung` spectrum (nila → trust-blue → gold).
 */

const GRADIENT_ID = 'mega-mendung-stroke';

/** One Mega Mendung cloud = three nested upward arcs + a tiny inner curl. */
function CloudUnit({ x, baseline = 22 }: { x: number; baseline?: number }) {
  // Concentric half-circle "bumps" (radii 18 / 11 / 5) make the layered cloud.
  return (
    <g transform={`translate(${x} 0)`}>
      <path d={`M2 ${baseline}a18 18 0 0 1 36 0`} />
      <path d={`M9 ${baseline}a11 11 0 0 1 22 0`} />
      <path d={`M15 ${baseline}a5 5 0 0 1 10 0`} />
      {/* connecting trough to the next cloud */}
      <path d={`M38 ${baseline}q6 6 12 0`} fill="none" />
    </g>
  );
}

/**
 * Thin scalloped cloud divider. Spans its container width; sits well as a
 * section separator or the lower edge of the header band.
 */
export function CloudDivider({
  className = '',
  units = 8,
  opacity = 0.5,
}: {
  className?: string;
  units?: number;
  opacity?: number;
}) {
  const step = 50; // CloudUnit footprint (cloud + trough)
  const width = units * step;
  return (
    <svg
      aria-hidden="true"
      className={className}
      viewBox={`0 0 ${width} 26`}
      width="100%"
      height="26"
      preserveAspectRatio="xMidYMid slice"
      role="presentation"
    >
      <defs>
        <linearGradient id={GRADIENT_ID} x1="0" y1="0" x2="1" y2="0">
          <stop offset="0" stopColor="#26324b" />
          <stop offset="0.45" stopColor="#2748b0" />
          <stop offset="0.72" stopColor="#6f86c9" />
          <stop offset="1" stopColor="#c8962f" />
        </linearGradient>
      </defs>
      <g
        fill="none"
        stroke={`url(#${GRADIENT_ID})`}
        strokeWidth="1.4"
        strokeLinecap="round"
        strokeLinejoin="round"
        opacity={opacity}
      >
        {Array.from({ length: units }, (_, i) => (
          <CloudUnit key={i} x={i * step} />
        ))}
      </g>
    </svg>
  );
}

/**
 * Soft hero ornament: a larger drift of stacked Mega Mendung clouds, faded into
 * the corner so headline text stays on a calm area. Purely atmospheric.
 */
export function MegaMendungOrnament({ className = '' }: { className?: string }) {
  return (
    <svg
      aria-hidden="true"
      className={className}
      viewBox="0 0 320 180"
      fill="none"
      role="presentation"
    >
      <defs>
        <linearGradient id="mm-fill" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#2748b0" stopOpacity="0.10" />
          <stop offset="0.6" stopColor="#6f86c9" stopOpacity="0.10" />
          <stop offset="1" stopColor="#d9ab45" stopOpacity="0.14" />
        </linearGradient>
        <linearGradient id="mm-line" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0" stopColor="#26324b" />
          <stop offset="0.5" stopColor="#2748b0" />
          <stop offset="1" stopColor="#c8962f" />
        </linearGradient>
      </defs>
      {/* layered cloud silhouettes */}
      <g stroke="url(#mm-line)" strokeWidth="1.6" strokeLinecap="round" opacity="0.45">
        <path d="M20 150a60 60 0 0 1 120 0" fill="url(#mm-fill)" />
        <path d="M44 150a36 36 0 0 1 72 0" />
        <path d="M64 150a16 16 0 0 1 32 0" />
        <path d="M150 150a78 78 0 0 1 156 0" fill="url(#mm-fill)" />
        <path d="M180 150a48 48 0 0 1 96 0" />
        <path d="M206 150a22 22 0 0 1 44 0" />
        <path d="M228 150a8 8 0 0 1 16 0" />
      </g>
    </svg>
  );
}
