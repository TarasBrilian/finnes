'use client';

import { Parallax } from '@/components/Parallax';

/** The supplied Cirebon Mega Mendung pattern (royal-blue ground baked in). */
export const BATIK_SRC = '/vecteezy_batik-mega-mendung-blue-paattern_11219197.svg';

/**
 * Mega Mendung batik backdrop for the immersive landing. The pattern is the
 * supplied vecteezy asset, rendered as a slow parallax layer and blended into
 * the midnight theme with a dark scrim so headline text stays readable.
 *
 * `focus` controls where the scrim keeps the surface dark for text:
 *  - 'left'   — hero (text anchored left)
 *  - 'center' — closing CTA (text centred)
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
      {/* Batik field — drifts as you scroll (slower than the page) for a clear
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
