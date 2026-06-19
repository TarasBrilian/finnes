'use client';

import { useEffect, useRef } from 'react';
import type { CSSProperties, ReactNode } from 'react';

function prefersReducedMotion(): boolean {
  return (
    typeof window !== 'undefined' &&
    window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
  );
}

/**
 * Scroll-linked parallax. The element is translated on the Y axis in proportion
 * to its distance from the viewport centre, so it drifts as you scroll. A
 * positive `speed` moves it slower than the page (recedes); larger = stronger.
 *
 * Implementation is dependency-free: one passive scroll listener per instance,
 * coalesced through requestAnimationFrame. Disabled under reduced-motion.
 */
export function Parallax({
  speed = 0.15,
  className = '',
  style,
  children,
  'aria-hidden': ariaHidden,
}: {
  speed?: number;
  className?: string;
  style?: CSSProperties;
  children?: ReactNode;
  'aria-hidden'?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el || prefersReducedMotion()) return;

    let raf = 0;
    const update = () => {
      raf = 0;
      const rect = el.getBoundingClientRect();
      const viewport = window.innerHeight || 1;
      // Distance of the element centre from the viewport centre.
      const center = rect.top + rect.height / 2 - viewport / 2;
      const shift = -center * speed;
      el.style.transform = `translate3d(0, ${shift.toFixed(1)}px, 0)`;
    };
    const onScroll = () => {
      if (!raf) raf = window.requestAnimationFrame(update);
    };

    update();
    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', onScroll);
    return () => {
      window.removeEventListener('scroll', onScroll);
      window.removeEventListener('resize', onScroll);
      if (raf) window.cancelAnimationFrame(raf);
    };
  }, [speed]);

  return (
    <div ref={ref} className={className} style={{ willChange: 'transform', ...style }} aria-hidden={ariaHidden}>
      {children}
    </div>
  );
}

/**
 * Reveals children on first scroll into view (fade + rise). Relies on the
 * `.reveal` / `.is-visible` utilities in globals.css. `delay` (ms) staggers
 * sibling reveals.
 */
export function Reveal({
  delay = 0,
  className = '',
  as: Tag = 'div',
  children,
}: {
  delay?: number;
  className?: string;
  as?: 'div' | 'section' | 'li' | 'article';
  children?: ReactNode;
}) {
  const ref = useRef<HTMLElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (prefersReducedMotion()) {
      el.classList.add('is-visible');
      return;
    }
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) {
            el.classList.add('is-visible');
            io.unobserve(el);
          }
        }
      },
      { threshold: 0.18, rootMargin: '0px 0px -8% 0px' },
    );
    io.observe(el);
    return () => io.disconnect();
  }, []);

  const Comp = Tag as any;
  return (
    <Comp ref={ref} className={`reveal ${className}`} style={{ transitionDelay: `${delay}ms` }}>
      {children}
    </Comp>
  );
}
