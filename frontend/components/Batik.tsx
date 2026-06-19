/**
 * Mega Mendung (Cirebon cloud batik) presentation helpers.
 *
 * The motif is a real asset - `public/mega-mendung.svg` (refined line-art) and
 * `public/seal.svg` (the brand roundel). Used as a restrained brand signature on
 * navy surfaces, never a full-page wallpaper. Decorative: `aria-hidden`.
 */

/**
 * Deep navy brand panel carrying the Mega Mendung line-art as a soft watermark
 * drifting in from the right. Children render on top (white text), anchored to
 * the calmer left side.
 */
export function MegaMendungBanner({
  children,
  className = '',
}: {
  children?: React.ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel-navy ${className}`}>
      {/* Line-art clouds, faint, on the right. */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -right-10 top-1/2 hidden h-[140%] w-2/3 -translate-y-1/2 bg-contain bg-right bg-no-repeat opacity-60 sm:block"
        style={{ backgroundImage: 'url(/mega-mendung.svg)' }}
      />
      {/* Readability scrim so headline text stays crisp over the clouds. */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 bg-gradient-to-r from-[#0c1c44] via-[#0c1c44]/80 to-transparent"
      />
      {/* Soft top glow. */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -left-20 -top-24 h-64 w-64 rounded-full bg-blue-500/20 blur-3xl"
      />
      <div className="relative">{children}</div>
    </section>
  );
}
