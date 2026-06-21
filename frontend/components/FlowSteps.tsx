'use client';

import { useEffect, useState } from 'react';
import { Reveal } from '@/components/Parallax';

export type FlowStep = { n: string; t: string; d: string };

/**
 * The "From deposit to disclosure" flow. A glowing highlight travels slowly from
 * step 1 → 2 → 3 → 4 and loops: the active step's numbered circle lights up
 * (filled accent + a soft pinging ring) while the others stay quiet. The cycle
 * pauses under prefers-reduced-motion (no traveling highlight, all steps shown
 * in their resting state).
 */
export function FlowSteps({ steps, intervalMs = 1900 }: { steps: FlowStep[]; intervalMs?: number }) {
  const [active, setActive] = useState(0);
  const [animate, setAnimate] = useState(false);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    if (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) return;
    setAnimate(true);
    const id = window.setInterval(() => {
      setActive((i) => (i + 1) % steps.length);
    }, intervalMs);
    return () => window.clearInterval(id);
  }, [steps.length, intervalMs]);

  return (
    <div className="mt-16 grid gap-10 md:grid-cols-2 lg:grid-cols-4">
      {steps.map((f, i) => {
        const isActive = animate && i === active;
        return (
          <Reveal key={f.t} delay={i * 90}>
            <div className="relative">
              <div className="flex items-center gap-3">
                <span className="relative grid h-10 w-10 shrink-0 place-items-center">
                  {isActive && (
                    <span className="absolute inset-0 rounded-full bg-accent/30 animate-ping" aria-hidden />
                  )}
                  <span
                    className={`relative grid h-10 w-10 place-items-center rounded-full border font-display text-base font-bold transition-all duration-500 ${
                      isActive
                        ? 'border-accent bg-accent text-midnight shadow-glow'
                        : 'border-accent/40 bg-accent/10 text-accent'
                    }`}
                  >
                    {f.n}
                  </span>
                </span>
                {i < steps.length - 1 && (
                  <span
                    className={`hidden h-px flex-1 bg-gradient-to-r to-transparent transition-colors duration-500 lg:block ${
                      isActive ? 'from-accent' : 'from-accent/40'
                    }`}
                  />
                )}
              </div>
              <h3
                className={`mt-5 font-display text-xl font-bold tracking-tight transition-colors duration-500 ${
                  isActive ? 'text-accent' : 'text-white'
                }`}
              >
                {f.t}
              </h3>
              <p className="mt-2.5 text-sm leading-relaxed text-white/60">{f.d}</p>
            </div>
          </Reveal>
        );
      })}
    </div>
  );
}
