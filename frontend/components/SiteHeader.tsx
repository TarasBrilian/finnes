'use client';

import { usePathname } from 'next/navigation';
import { useEffect, useState } from 'react';
import { HeaderWalletButton } from '@/components/HeaderWalletButton';

/**
 * Top navigation. Adapts to the surface it sits on: a transparent, dark-aware
 * bar over the immersive landing (which gains a blurred midnight backing once
 * you scroll), and the light institutional bar on the consoles.
 */
export function SiteHeader() {
  const pathname = usePathname();
  const dark = pathname === '/';
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    if (!dark) return;
    const onScroll = () => setScrolled(window.scrollY > 24);
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, [dark]);

  const shell = dark
    ? scrolled
      ? 'border-white/10 bg-midnight/85 backdrop-blur-xl'
      : 'border-transparent bg-gradient-to-b from-midnight via-midnight/80 to-transparent'
    : 'border-blue-100 bg-white/80 backdrop-blur-md';

  const wordmark = dark ? 'text-white' : 'text-ink';
  const wordmarkSub = dark ? 'text-accent/90' : 'text-blue-500';
  const navLink = dark
    ? 'rounded-lg px-3 py-1.5 text-white/70 transition hover:bg-white/10 hover:text-white'
    : 'rounded-lg px-3 py-1.5 transition hover:bg-blue-50 hover:text-blue-700';

  return (
    <header className={`sticky top-0 z-30 border-b transition-colors duration-300 ${shell}`}>
      <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-3.5">
        <a href="/" className="group flex items-center gap-3">
          <img src="/seal.svg" alt="" aria-hidden="true" className="h-9 w-9" />
          <span className="flex flex-col leading-none">
            <span className={`font-display text-[18px] font-bold tracking-tight ${wordmark}`}>Finnes</span>
            <span className={`mt-1 hidden text-[10px] font-semibold uppercase tracking-[0.18em] sm:inline ${wordmarkSub}`}>
              confidential RWA settlement
            </span>
          </span>
        </a>
        <div className="flex items-center gap-2">
          <nav className={`mr-2 hidden items-center gap-1 text-sm font-medium sm:flex ${dark ? 'text-white/70' : 'text-ink-muted'}`}>
            <a href="/institution" className={navLink}>Institution</a>
            <a href="/regulator" className={navLink}>Regulator</a>
          </nav>
          <HeaderWalletButton />
        </div>
      </div>
    </header>
  );
}
