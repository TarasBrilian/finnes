'use client';

import { Parallax } from '@/components/Parallax';

/** The supplied Cirebon Mega Mendung pattern (royal-blue ground baked in). */
export const BATIK_SRC = '/vecteezy_batik-mega-mendung-blue-paattern_11219197.svg';

/** A finer Mega Mendung cloud-row pattern (near-white ground). Used tinted, as
 *  a textile ribbon / faint texture, so it fits the dark vault theme. */
export const BATIK_BG_SRC = '/vecteezy_megamendung-batik-background-vector_105799.svg';

/**
 * A full-bleed Mega Mendung "textile ribbon" — a horizontal band of the finer
 * batik pattern that acts as a section divider. The light asset is darkened and
 * blue-tinted to sit inside the midnight theme, its top/bottom edges fade into
 * the surrounding sections, and the left/right edges dissolve via the marquee
 * mask. `bg-top` crops the source so the vendor watermark (bottom-centre) is
 * never shown. Decorative: aria-hidden.
 */
export function BatikRibbon({ className = '' }: { className?: string }) {
  return (
    <div
      aria-hidden="true"
      className={`full-bleed relative h-32 overflow-hidden border-y border-white/10 bg-midnight-900 sm:h-40 ${className}`}
    >
      {/* Batik field, cropped to the top so the watermark is excluded. */}
      <div
        className="marquee-mask absolute inset-0 bg-cover bg-top"
        style={{ backgroundImage: `url(${BATIK_BG_SRC})` }}
      />
      {/* Blue-tint + darken so the near-white asset reads as deep batik. */}
      <div className="absolute inset-0 bg-midnight/55" />
      <div className="absolute inset-0 bg-blue-900/30 mix-blend-multiply" />
      {/* Seat the band into the sections above and below. */}
      <div className="absolute inset-x-0 top-0 h-10 bg-gradient-to-b from-midnight to-transparent" />
      <div className="absolute inset-x-0 bottom-0 h-10 bg-gradient-to-t from-midnight to-transparent" />
    </div>
  );
}

/**
 * A faint, tinted Mega Mendung texture for the corner of a dark section — the
 * finer pattern at low opacity, anchored to one side, dissolving across. Sits
 * behind content (pointer-events-none, aria-hidden).
 */
export function BatikTexture({
  side = 'right',
  className = '',
}: {
  side?: 'left' | 'right';
  className?: string;
}) {
  const fade = side === 'right' ? 'left' : 'right';
  return (
    <div aria-hidden="true" className={`pointer-events-none absolute inset-0 overflow-hidden ${className}`}>
      <div
        className="absolute inset-y-0 w-2/3 bg-cover bg-center opacity-[0.07]"
        style={{
          backgroundImage: `url(${BATIK_BG_SRC})`,
          [side]: 0,
          maskImage: `linear-gradient(to ${fade}, #000 10%, transparent 85%)`,
          WebkitMaskImage: `linear-gradient(to ${fade}, #000 10%, transparent 85%)`,
        }}
      />
    </div>
  );
}

/**
 * Mega Mendung batik backdrop for the immersive landing. The pattern is the
 * supplied vecteezy asset, rendered as a slow parallax layer and blended into
 * the midnight theme with a dark scrim so headline text stays readable.
 *
 * `focus` controls where the scrim keeps the surface dark for text:
 *  - 'left'  , hero (text anchored left)
 *  - 'center', closing CTA (text centred)
 *
 * Decorative: aria-hidden.
 */
export function BatikBackdrop({
  focus = 'left',
  className = '',
}: {
  focus?: 'left' | 'center';
  className?: string;
}) {
  return (
    <div aria-hidden="true" className={`pointer-events-none absolute inset-0 overflow-hidden ${className}`}>
      {/* Batik field, drifts as you scroll (slower than the page) for a clear
          parallax. The generous negative inset keeps the larger translate from
          revealing the section edges. */}
      <Parallax speed={0.3} className="absolute inset-0">
        <div
          className="absolute inset-[-35%] bg-cover bg-center"
          style={{ backgroundImage: `url(${BATIK_SRC})` }}
        />
      </Parallax>

      {/* Overall darken so the vivid batik reads as part of the dark theme. */}
      <div className="absolute inset-0 bg-midnight/40" />

      {/* Readability scrim. */}
      {focus === 'left' ? (
        <div className="absolute inset-0 bg-gradient-to-r from-midnight via-midnight/80 to-transparent" />
      ) : (
        <div
          className="absolute inset-0"
          style={{
            background:
              'radial-gradient(60% 70% at 50% 50%, rgba(6,12,31,0.82) 0%, rgba(6,12,31,0.45) 55%, rgba(6,12,31,0) 100%)',
          }}
        />
      )}

      {/* Top + bottom fades blend into the surrounding midnight sections. */}
      <div className="absolute inset-x-0 top-0 h-24 bg-gradient-to-b from-midnight to-transparent" />
      <div className="absolute inset-x-0 bottom-0 h-44 bg-gradient-to-t from-midnight to-transparent" />
    </div>
  );
}
